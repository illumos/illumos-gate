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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This file contains logic to walk and print a large chunk of configuration
 * space and many of the capabilities. There are multiple sub-commands that
 * vector into the same logic (e.g. 'save-cfgspace' and 'show-cfgspace'). In
 * general, there are a few major goals with this bit of code:
 *
 *  o Every field should strive to be parsable and therefore selectable for
 *    output. This drove the idea that every field has both a short name and a
 *    human name. The short name is a dot-delineated name. When in parsable
 *    mode, the name will always refer to a single field. However, for
 *    convenience for humans, when not trying to be parsable, we show the
 *    parents in the tree. That is if you specify something like
 *    'pcie.linkcap.maxspeed', in parsable mode you'll only get that; however,
 *    in non-parsable mode, you'll get an indication of the capability and
 *    register that field was in.
 *
 *  o Related to the above, parsable mode always outputs a raw, uninterpreted
 *    value. This was done on purpose. Some fields require interpreting multiple
 *    registers to have meaning and long strings aren't always the most useful.
 *
 *  o Every field isn't always pretty printed. This was generally just a
 *    decision based upon the field itself and how much work it'd be to fit it
 *    into the framework we have. In general, the ones we're mostly guilty of
 *    doing this with are related to cases where there's a scaling value in a
 *    subsequent register. If you find yourself wanting this, feel free to add
 *    it.
 *
 *  o Currently designated vendor-specific capabilities aren't included here (or
 *    any specific vendor-specific capabilities for that matter). If they are
 *    added, they should follow the same angle of using a name to represent a
 *    sub-capability as we did with HyperTransport.
 */

#include <err.h>
#include <strings.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/debug.h>
#include <ofmt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/bitext.h>

#include "pcieadm.h"

typedef enum pcieadm_cfgspace_op {
	PCIEADM_CFGSPACE_OP_PRINT,
	PCIEADM_CFGSPACE_OP_WRITE
} pcieadm_cfgspace_op_t;

typedef enum piceadm_cfgspace_flag {
	PCIEADM_CFGSPACE_F_PARSE	= 1 << 0,
	PCIEADM_CFGSPACE_F_SHORT	= 1 << 1,
} pcieadm_cfgspace_flags_t;

typedef enum pcieadm_cfgspace_otype {
	PCIEADM_CFGSPACE_OT_SHORT,
	PCIEADM_CFGSPACE_OT_HUMAN,
	PCIEADM_CFGSPACE_OT_VALUE
} pcieadm_cfgsapce_otype_t;

typedef struct pcieadm_cfgspace_ofmt {
	const char *pco_base;
	const char *pco_short;
	const char *pco_human;
	uint64_t pco_value;
	const char *pco_strval;
} pcieadm_cfgspace_ofmt_t;

typedef enum pcieadm_regdef_val {
	PRDV_STRVAL,
	PRDV_BITFIELD,
	PRDV_HEX
} pcieadm_regdef_val_t;

typedef struct pcieadm_regdef_addend {
	uint8_t pra_shift;
	int64_t pra_addend;
} pcieadm_regdef_addend_t;

typedef struct pcieadm_regdef {
	uint8_t prd_lowbit;
	uint8_t prd_hibit;
	const char *prd_short;
	const char *prd_human;
	pcieadm_regdef_val_t prd_valtype;
	union {
		/*
		 * Enough space for up to an 8-bit fields worth of values
		 * (though we expect most to be sparse).
		 */
		const char *prdv_strval[128];
		pcieadm_regdef_addend_t prdv_hex;
	} prd_val;
} pcieadm_regdef_t;

typedef struct pcieadm_unitdef {
	const char *pcd_unit;
	uint32_t pcd_mult;
} pcieadm_unitdef_t;

typedef struct pcieadm_strmap {
	const char *psr_str;
	uint64_t psr_val;
} pcieadm_strmap_t;

typedef struct pcieadm_cfgspace_filter {
	const char *pcf_string;
	size_t pcf_len;
	boolean_t pcf_used;
} pcieadm_cfgspace_filter_t;

typedef struct pcieadm_strfilt {
	struct pcieadm_strfilt *pstr_next;
	const char *pstr_str;
	char pstr_curgen[256];
} pcieadm_strfilt_t;

/*
 * Data is sized to be large enough that we can hold all of PCIe extended
 * configuration space.
 */
typedef union pcieadm_cfgspace_data {
	uint8_t pcb_u8[PCIE_CONF_HDR_SIZE];
	uint32_t pcb_u32[PCIE_CONF_HDR_SIZE / 4];
} pcieadm_cfgspace_data_t;

typedef struct pcieadm_cfgspace_walk {
	pcieadm_t *pcw_pcieadm;
	pcieadm_cfgspace_op_t pcw_op;
	uint32_t pcw_valid;
	pcieadm_cfgspace_data_t *pcw_data;
	uint16_t pcw_capoff;
	uint32_t pcw_caplen;
	int pcw_outfd;
	uint_t pcw_dtype;
	uint_t pcw_nlanes;
	uint_t pcw_pcietype;
	uint_t pcw_nfilters;
	pcieadm_cfgspace_filter_t *pcw_filters;
	pcieadm_cfgspace_flags_t pcw_flags;
	ofmt_handle_t pcw_ofmt;
	pcieadm_strfilt_t *pcw_filt;
} pcieadm_cfgspace_walk_t;

void
pcieadm_strfilt_pop(pcieadm_cfgspace_walk_t *walkp)
{
	pcieadm_strfilt_t *filt;

	VERIFY3P(walkp->pcw_filt, !=, NULL);
	filt = walkp->pcw_filt;
	walkp->pcw_filt = filt->pstr_next;
	free(filt);
}

void
pcieadm_strfilt_push(pcieadm_cfgspace_walk_t *walkp, const char *str)
{
	pcieadm_strfilt_t *filt;
	size_t len;

	filt = calloc(1, sizeof (*filt));
	if (filt == NULL) {
		errx(EXIT_FAILURE, "failed to allocate memory for string "
		    "filter");
	}

	filt->pstr_str = str;
	if (walkp->pcw_filt == NULL) {
		len = strlcat(filt->pstr_curgen, str,
		    sizeof (filt->pstr_curgen));
	} else {
		len = snprintf(filt->pstr_curgen, sizeof (filt->pstr_curgen),
		    "%s.%s", walkp->pcw_filt->pstr_curgen, str);
		filt->pstr_next = walkp->pcw_filt;
	}

	if (len >= sizeof (filt->pstr_curgen)) {
		errx(EXIT_FAILURE, "overflowed internal string buffer "
		    "appending %s", str);
	}

	walkp->pcw_filt = filt;
}

static boolean_t
pcieadm_cfgspace_filter(pcieadm_cfgspace_walk_t *walkp, const char *str)
{
	char buf[1024];
	size_t len;

	if (walkp->pcw_nfilters == 0) {
		return (B_TRUE);
	}

	if (str == NULL) {
		return (B_FALSE);
	}

	if (walkp->pcw_filt != NULL) {
		len = snprintf(buf, sizeof (buf), "%s.%s",
		    walkp->pcw_filt->pstr_curgen, str);
	} else {
		len = snprintf(buf, sizeof (buf), "%s", str);
	}

	if (len >= sizeof (buf)) {
		abort();
	}

	for (uint_t i = 0; i < walkp->pcw_nfilters; i++) {
		if (strcmp(buf, walkp->pcw_filters[i].pcf_string) == 0) {
			walkp->pcw_filters[i].pcf_used = B_TRUE;
			return (B_TRUE);
		}

		/*
		 * If we're in non-parsable mode, we want to do a little bit
		 * more in a few cases. We want to make sure that we print the
		 * parents of more-specific entries. That is, if someone
		 * specified 'header.command.serr', then we want to print
		 * 'header', and 'header.command'. Similarly, if someone
		 * specifies an individual field, we want to print all of its
		 * subfields, that is asking for 'header.command', really gets
		 * that and all of 'header.command.*'.
		 */
		if ((walkp->pcw_flags & PCIEADM_CFGSPACE_F_PARSE) != 0) {
			continue;
		}

		if (len >= walkp->pcw_filters[i].pcf_len) {
			if (strncmp(buf, walkp->pcw_filters[i].pcf_string,
			    walkp->pcw_filters[i].pcf_len) == 0 &&
			    buf[walkp->pcw_filters[i].pcf_len] == '.') {
				return (B_TRUE);
			}
		} else {
			if (strncmp(buf, walkp->pcw_filters[i].pcf_string,
			    len) == 0 &&
			    walkp->pcw_filters[i].pcf_string[len] == '.') {
				return (B_TRUE);
			}
		}
	}

	return (B_FALSE);
}

static boolean_t
pcieadm_cfgspace_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	pcieadm_cfgspace_ofmt_t *pco = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case PCIEADM_CFGSPACE_OT_SHORT:
		if (snprintf(buf, buflen, "%s.%s", pco->pco_base,
		    pco->pco_short) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_CFGSPACE_OT_HUMAN:
		if (strlcpy(buf, pco->pco_human, buflen) >= buflen) {
			return (B_FALSE);
		}
		break;
	case PCIEADM_CFGSPACE_OT_VALUE:
		if (pco->pco_strval != NULL) {
			if (strlcpy(buf, pco->pco_strval, buflen) >= buflen) {
				return (B_FALSE);
			}
		} else {
			if (snprintf(buf, buflen, "0x%" PRIx64,
			    pco->pco_value) >= buflen) {
				return (B_FALSE);
			}
		}
		break;
	default:
		abort();
	}

	return (B_TRUE);
}


static const ofmt_field_t pcieadm_cfgspace_ofmt[] = {
	{ "SHORT", 30, PCIEADM_CFGSPACE_OT_SHORT, pcieadm_cfgspace_ofmt_cb },
	{ "HUMAN", 30, PCIEADM_CFGSPACE_OT_HUMAN, pcieadm_cfgspace_ofmt_cb },
	{ "VALUE", 20, PCIEADM_CFGSPACE_OT_VALUE, pcieadm_cfgspace_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

static void
pcieadm_cfgspace_print_parse(pcieadm_cfgspace_walk_t *walkp,
    const char *sname, const char *human, uint64_t value)
{
	pcieadm_cfgspace_ofmt_t pco;

	VERIFY3P(walkp->pcw_filt, !=, NULL);
	pco.pco_base = walkp->pcw_filt->pstr_curgen;
	pco.pco_short = sname;
	pco.pco_human = human;
	pco.pco_value = value;
	pco.pco_strval = NULL;
	ofmt_print(walkp->pcw_ofmt, &pco);
}

typedef struct pcieadm_cfgspace_print pcieadm_cfgspace_print_t;
typedef void (*pcieadm_cfgspace_print_f)(pcieadm_cfgspace_walk_t *,
    const pcieadm_cfgspace_print_t *, const void *);

struct pcieadm_cfgspace_print {
	uint8_t pcp_off;
	uint8_t pcp_len;
	const char *pcp_short;
	const char *pcp_human;
	pcieadm_cfgspace_print_f pcp_print;
	const void *pcp_arg;
};

static void
pcieadm_field_printf(pcieadm_cfgspace_walk_t *walkp, const char *shortf,
    const char *humanf, uint64_t val, const char *fmt, ...)
{
	va_list ap;

	if (!pcieadm_cfgspace_filter(walkp, shortf))
		return;

	if (walkp->pcw_ofmt != NULL) {
		pcieadm_cfgspace_print_parse(walkp, shortf, humanf, val);
		return;
	}

	if (walkp->pcw_pcieadm->pia_indent > 0) {
		(void) printf("%*s", walkp->pcw_pcieadm->pia_indent, "");
	}

	if ((walkp->pcw_flags & PCIEADM_CFGSPACE_F_SHORT) != 0) {
		(void) printf("|--> %s (%s.%s): ", humanf,
		    walkp->pcw_filt->pstr_curgen, shortf);
	} else {
		(void) printf("|--> %s: ", humanf);
	}

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);

}

static void
pcieadm_cfgspace_printf(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, uint64_t val, const char *fmt, ...)
{
	va_list ap;

	if (!pcieadm_cfgspace_filter(walkp, print->pcp_short))
		return;

	if (walkp->pcw_ofmt != NULL) {
		pcieadm_cfgspace_print_parse(walkp, print->pcp_short,
		    print->pcp_human, val);
		return;
	}

	if (walkp->pcw_pcieadm->pia_indent > 0) {
		(void) printf("%*s", walkp->pcw_pcieadm->pia_indent, "");
	}

	if ((walkp->pcw_flags & PCIEADM_CFGSPACE_F_SHORT) != 0) {
		(void) printf("%s (%s.%s): ", print->pcp_human,
		    walkp->pcw_filt->pstr_curgen, print->pcp_short);
	} else {
		(void) printf("%s: ", print->pcp_human);
	}

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

static void
pcieadm_cfgspace_puts(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const char *str)
{
	if (!pcieadm_cfgspace_filter(walkp, print->pcp_short))
		return;

	if (walkp->pcw_ofmt != NULL) {
		pcieadm_cfgspace_ofmt_t pco;

		VERIFY3P(walkp->pcw_filt, !=, NULL);
		pco.pco_base = walkp->pcw_filt->pstr_curgen;
		pco.pco_short = print->pcp_short;
		pco.pco_human = print->pcp_human;
		pco.pco_strval = str;
		ofmt_print(walkp->pcw_ofmt, &pco);
		return;
	}

	if (walkp->pcw_pcieadm->pia_indent > 0) {
		(void) printf("%*s", walkp->pcw_pcieadm->pia_indent, "");
	}

	if ((walkp->pcw_flags & PCIEADM_CFGSPACE_F_SHORT) != 0) {
		(void) printf("%s (%s.%s): %s\n", print->pcp_human,
		    walkp->pcw_filt->pstr_curgen, print->pcp_short, str);
	} else {
		(void) printf("%s: %s\n", print->pcp_human, str);
	}
}

static uint64_t
pcieadm_cfgspace_extract(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print)
{
	uint32_t val = 0;

	VERIFY3U(print->pcp_len, <=, 8);
	VERIFY3U(print->pcp_off + print->pcp_len + walkp->pcw_capoff, <=,
	    walkp->pcw_valid);
	for (uint8_t i = print->pcp_len; i > 0; i--) {
		val <<= 8;
		val |= walkp->pcw_data->pcb_u8[walkp->pcw_capoff +
		    print->pcp_off + i - 1];
	}

	return (val);
}

static uint16_t
pcieadm_cfgspace_extract_u16(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print)
{
	VERIFY(print->pcp_len == 2);
	return ((uint16_t)pcieadm_cfgspace_extract(walkp, print));
}

static void
pcieadm_cfgspace_print_unit(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	const pcieadm_unitdef_t *unit = arg;
	uint64_t rawval = pcieadm_cfgspace_extract(walkp, print);
	uint64_t val = rawval;

	if (unit->pcd_mult > 1) {
		val *= unit->pcd_mult;
	}
	pcieadm_cfgspace_printf(walkp, print, rawval, "0x%" PRIx64 " %s%s\n",
	    val, unit->pcd_unit, val != 1 ? "s" : "");
}

static void
pcieadm_cfgspace_print_regdef(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	const pcieadm_regdef_t *regdef = arg;
	uint64_t val = pcieadm_cfgspace_extract(walkp, print);

	pcieadm_cfgspace_printf(walkp, print, val, "0x%" PRIx64 "\n", val);

	pcieadm_indent();
	pcieadm_strfilt_push(walkp, print->pcp_short);

	for (regdef = arg; regdef->prd_short != NULL; regdef++) {
		uint32_t nbits = regdef->prd_hibit - regdef->prd_lowbit + 1UL;
		uint32_t bitmask = (1UL << nbits) - 1UL;
		uint64_t regval = (val >> regdef->prd_lowbit) & bitmask;
		const char *strval;
		uint64_t actval;

		if (!pcieadm_cfgspace_filter(walkp, regdef->prd_short)) {
			continue;
		}

		switch (regdef->prd_valtype) {
		case PRDV_STRVAL:
			strval = regdef->prd_val.prdv_strval[regval];
			if (strval == NULL) {
				strval = "reserved";
			}

			pcieadm_field_printf(walkp, regdef->prd_short,
			    regdef->prd_human, regval, "%s (0x%" PRIx64 ")\n",
			    strval, regval << regdef->prd_lowbit);
			break;
		case PRDV_HEX:
			actval = regval;
			if (regdef->prd_val.prdv_hex.pra_shift > 0) {
				actval <<= regdef->prd_val.prdv_hex.pra_shift;
			}
			actval += regdef->prd_val.prdv_hex.pra_addend;

			pcieadm_field_printf(walkp, regdef->prd_short,
			    regdef->prd_human, regval, "0x% " PRIx64 "\n",
			    actval);
			break;
		case PRDV_BITFIELD:
			pcieadm_field_printf(walkp, regdef->prd_short,
			    regdef->prd_human, regval, "0x%" PRIx64 "\n",
			    regval << regdef->prd_lowbit);

			if (walkp->pcw_ofmt == NULL) {
				pcieadm_indent();
				for (uint32_t i = 0; i < nbits; i++) {
					if (((1 << i) & regval) == 0)
						continue;
					pcieadm_print("|--> %s (0x%x)\n",
					    regdef->prd_val.prdv_strval[i],
					    1UL << (i + regdef->prd_lowbit));
				}
				pcieadm_deindent();
			}
			break;
		}
	}

	pcieadm_strfilt_pop(walkp);
	pcieadm_deindent();
}

static void
pcieadm_cfgspace_print_strmap(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	const pcieadm_strmap_t *strmap = arg;
	uint64_t val = pcieadm_cfgspace_extract(walkp, print);
	const char *str = "reserved";

	for (uint_t i = 0; strmap[i].psr_str != NULL; i++) {
		if (strmap[i].psr_val == val) {
			str = strmap[i].psr_str;
			break;
		}
	}

	pcieadm_cfgspace_printf(walkp, print, val, "0x%x -- %s\n", val, str);
}

static void
pcieadm_cfgspace_print_hex(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint64_t val = pcieadm_cfgspace_extract(walkp, print);

	pcieadm_cfgspace_printf(walkp, print, val, "0x%" PRIx64 "\n", val);
}

static void
pcieadm_cfgspace_print_vendor(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	pcidb_vendor_t *vend;
	uint16_t vid = pcieadm_cfgspace_extract_u16(walkp, print);

	vend = pcidb_lookup_vendor(walkp->pcw_pcieadm->pia_pcidb, vid);
	if (vend != NULL) {
		pcieadm_cfgspace_printf(walkp, print, vid, "0x%x -- %s\n", vid,
		    pcidb_vendor_name(vend));
	} else {
		pcieadm_cfgspace_printf(walkp, print, vid, "0x%x\n", vid);
	}
}

static void
pcieadm_cfgspace_print_device(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	pcidb_device_t *dev;
	uint16_t did = pcieadm_cfgspace_extract_u16(walkp, print);
	uint16_t vid = walkp->pcw_data->pcb_u8[PCI_CONF_VENID] +
	    (walkp->pcw_data->pcb_u8[PCI_CONF_VENID + 1] << 8);

	dev = pcidb_lookup_device(walkp->pcw_pcieadm->pia_pcidb, vid, did);
	if (dev != NULL) {
		pcieadm_cfgspace_printf(walkp, print, did, "0x%x -- %s\n", did,
		    pcidb_device_name(dev));
	} else {
		pcieadm_cfgspace_printf(walkp, print, did, "0x%x\n", did);
	}
}

/*
 * To print out detailed information about a subsystem vendor or device, we need
 * all of the information about the vendor and device due to the organization of
 * the PCI IDs db.
 */
static void
pcieadm_cfgspace_print_subid(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint16_t vid = walkp->pcw_data->pcb_u8[PCI_CONF_VENID] +
	    (walkp->pcw_data->pcb_u8[PCI_CONF_VENID + 1] << 8);
	uint16_t did = walkp->pcw_data->pcb_u8[PCI_CONF_DEVID] +
	    (walkp->pcw_data->pcb_u8[PCI_CONF_DEVID + 1] << 8);
	uint16_t svid = walkp->pcw_data->pcb_u8[PCI_CONF_SUBVENID] +
	    (walkp->pcw_data->pcb_u8[PCI_CONF_SUBVENID + 1] << 8);
	uint16_t sdid = walkp->pcw_data->pcb_u8[PCI_CONF_SUBSYSID] +
	    (walkp->pcw_data->pcb_u8[PCI_CONF_SUBSYSID + 1] << 8);
	uint16_t val = pcieadm_cfgspace_extract_u16(walkp, print);
	boolean_t isvendor = print->pcp_off == PCI_CONF_SUBVENID;

	if (isvendor) {
		pcidb_vendor_t *vend;
		vend = pcidb_lookup_vendor(walkp->pcw_pcieadm->pia_pcidb,
		    svid);
		if (vend != NULL) {
			pcieadm_cfgspace_printf(walkp, print, val,
			    "0x%x -- %s\n", val, pcidb_vendor_name(vend));
		} else {
			pcieadm_cfgspace_printf(walkp, print, val,
			    "0x%x\n", val);
		}
	} else {
		pcidb_subvd_t *subvd;
		subvd = pcidb_lookup_subvd(walkp->pcw_pcieadm->pia_pcidb, vid,
		    did, svid, sdid);
		if (subvd != NULL) {
			pcieadm_cfgspace_printf(walkp, print, val,
			    "0x%x -- %s\n", val, pcidb_subvd_name(subvd));
		} else {
			pcieadm_cfgspace_printf(walkp, print, val, "0x%x\n",
			    val);
		}
	}
}

/*
 * The variable natures of BARs is a pain. This makes printing this out and the
 * fields all a bit gross.
 */
static void
pcieadm_cfgspace_print_bars(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint32_t *barp = &walkp->pcw_data->pcb_u32[(walkp->pcw_capoff +
	    print->pcp_off) / 4];
	char barname[32];
	const char *typestrs[2] = { "Memory Space", "I/O Space" };

	for (uint_t i = 0; i < print->pcp_len / 4; i++) {
		uint_t type;
		(void) snprintf(barname, sizeof (barname), "%s%u",
		    print->pcp_short, i);

		type = barp[i] & PCI_BASE_SPACE_M;

		if (pcieadm_cfgspace_filter(walkp, barname) &&
		    walkp->pcw_ofmt == NULL) {
			if ((walkp->pcw_flags & PCIEADM_CFGSPACE_F_SHORT) !=
			    0) {
				pcieadm_print("%s %u (%s.%s)\n",
				    print->pcp_human, i,
				    walkp->pcw_filt->pstr_curgen, barname);
			} else {
				pcieadm_print("%s %u\n", print->pcp_human, i);
			}
		}

		pcieadm_strfilt_push(walkp, barname);
		pcieadm_indent();

		pcieadm_field_printf(walkp, "space", "Space", type,
		    "%s (0x%x)\n", typestrs[type], type);

		if (type == PCI_BASE_SPACE_IO) {
			uint32_t addr = barp[i] & PCI_BASE_IO_ADDR_M;

			pcieadm_field_printf(walkp, "addr", "Address", addr,
			    "0x%" PRIx32 "\n", addr);
		} else {
			uint8_t type, pre;
			uint64_t addr;
			const char *locstr;

			type = barp[i] & PCI_BASE_TYPE_M;
			pre = barp[i] & PCI_BASE_PREF_M;
			addr = barp[i] & PCI_BASE_M_ADDR_M;

			if (type == PCI_BASE_TYPE_ALL) {
				addr += (uint64_t)barp[i+1] << 32;
				i++;
			}

			pcieadm_field_printf(walkp, "addr", "Address", addr,
			    "0x%" PRIx64 "\n", addr);

			switch (type) {
			case PCI_BASE_TYPE_MEM:
				locstr = "32-bit";
				break;
			case PCI_BASE_TYPE_LOW:
				locstr = "Sub-1 MiB";
				break;
			case PCI_BASE_TYPE_ALL:
				locstr = "64-bit";
				break;
			case PCI_BASE_TYPE_RES:
			default:
				locstr = "Reserved";
				break;
			}

			pcieadm_field_printf(walkp, "type", "Memory Type", addr,
			    "%s (0x%x)\n", locstr, type >> 1);
			pcieadm_field_printf(walkp, "prefetch", "Prefetchable",
			    pre != 0, "%s (0x%x)\n", pre != 0 ? "yes" : "no",
			    pre != 0);
		}

		pcieadm_deindent();
		pcieadm_strfilt_pop(walkp);
	}
}

static void
pcieadm_cfgspace_print_ecv(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint16_t bitlen, nwords;

	if (bitx8(walkp->pcw_data->pcb_u8[walkp->pcw_capoff + 4], 5, 5) == 0) {
		return;
	}

	bitlen = walkp->pcw_data->pcb_u8[walkp->pcw_capoff + 5];
	if (bitlen == 0) {
		bitlen = 256;
	}

	nwords = bitlen / 32;
	if ((bitlen % 8) != 0) {
		nwords++;
	}

	for (uint16_t i = 0; i < nwords; i++) {
		char tshort[32], thuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(tshort, sizeof (tshort), "ecv%u", i);
		(void) snprintf(thuman, sizeof (thuman), "Egress Control "
		    "Vector %u", i);
		p.pcp_off = print->pcp_off + i * 4;
		p.pcp_len = 4;
		p.pcp_short = tshort;
		p.pcp_human = thuman;
		p.pcp_print = pcieadm_cfgspace_print_hex;
		p.pcp_arg = NULL;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static void
pcieadm_cfgspace_print_dpa_paa(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint8_t nents;

	nents = bitx8(walkp->pcw_data->pcb_u8[walkp->pcw_capoff + 4], 4, 0) + 1;
	if (nents == 0) {
		return;
	}

	for (uint8_t i = 0; i < nents; i++) {
		char tshort[32], thuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(tshort, sizeof (tshort), "%s%u",
		    print->pcp_short, i);
		(void) snprintf(thuman, sizeof (thuman), "%s %u",
		    print->pcp_human, i);

		p.pcp_off = print->pcp_off + i;
		p.pcp_len = 1;
		p.pcp_short = tshort;
		p.pcp_human = thuman;
		p.pcp_print = pcieadm_cfgspace_print_hex;
		p.pcp_arg = NULL;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

/*
 * Config Space Header Table Definitions
 */
static const pcieadm_regdef_t pcieadm_regdef_command[] = {
	{ 0, 0, "io", "I/O Space", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "mem", "Memory Space", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "bus", "Bus Master", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "spec", "Special Cycle", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "mwi", "Memory Write and Invalidate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 5, "vga", "VGA Palette Snoop", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 6, "per", "Parity Error Response", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 7, 7, "idsel", "IDSEL Stepping/Wait Cycle Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "serr", "SERR# Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } }, },
	{ 9, 9, "fbtx", "Fast Back-to-Back Transactions", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } }, },
	{ 10, 10, "intx", "Interrupt X", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "enabled", "disabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_status[] = {
	{ 0, 0, "imm", "Immediate Readiness", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } }, },
	{ 3, 3, "istat", "Interrupt Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not pending", "pending" } }, },
	{ 4, 4, "capsup", "Capabilities List", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } }, },
	{ 5, 5, "66mhz", "66 MHz Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } }, },
	{ 7, 7, "fbtxcap", "Fast Back-to-Back Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } }, },
	{ 8, 8, "mdperr", "Master Data Parity Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no error", "error detected" } }, },
	{ 9, 10, "devsel", "DEVSEL# Timing", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "fast", "medium", "slow",
	    "reserved" } } },
	{ 11, 11, "sta", "Signaled Target Abort", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 12, 12, "rta", "Received Target Abort", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 13, 13, "rma", "Received Master Abort", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 14, 14, "sse", "Signaled System Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 15, 15, "dpe", "Detected Parity Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

/*
 * It might be interesting to translate these into numbers at a future point.
 */
static const pcieadm_regdef_t pcieadm_regdef_class[] = {
	{ 16, 23, "class", "Class Code", PRDV_HEX },
	{ 7, 15, "sclass", "Sub-Class Code", PRDV_HEX },
	{ 0, 7, "pi", "Programming Interface", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bridge_iobase[] = {
	{ 0, 3, "cap", "Addressing Capability", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "16-bit", "32-bit" } } },
	{ 4, 7, "base", "Base", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 12 } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bridge_iolim[] = {
	{ 0, 3, "cap", "Addressing Capability", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "16-bit", "32-bit" } } },
	{ 4, 7, "limit", "Limit", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 12, 0xfff } } },
	{ -1, -1, NULL }
};


static const pcieadm_regdef_t pcieadm_regdef_bridgests[] = {
	{ 5, 5, "66mhz", "66 MHz", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 7, 7, "fastb2b", "Fast Back-to-Back Transactions", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "mdperr", "Master Data Parity Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no error", "error detected" } } },
	{ 9, 10, "devsel", "DEVSEL# Timing", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "fast", "medium", "slow" } } },
	{ 11, 11, "sta", "Signaled Target Abort", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no abort", "aborted" } } },
	{ 12, 12, "rta", "Received Target Abort", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no abort", "aborted" } } },
	{ 13, 13, "rma", "Received Master Abort", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no abort", "aborted" } } },
	{ 14, 14, "rsyserr", "Received System Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no error", "error received" } } },
	{ 15, 15, "dperr", "Detected Parity Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no error", "error detected" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bridge_membase[] = {
	{ 4, 16, "base", "Base", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 20 } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bridge_memlim[] = {
	{ 4, 16, "limit", "Limit", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 20, 0xfffff } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bridge_pfbase[] = {
	{ 0, 3, "cap", "Addressing Capability", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "32-bit", "64-bit" } } },
	{ 4, 16, "base", "Base", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 20 } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bridge_pflim[] = {
	{ 0, 3, "cap", "Addressing Capability", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "32-bit", "64-bit" } } },
	{ 4, 16, "limit", "Limit", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 20, 0xfffff } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bridge_ctl[] = {
	{ 0, 0, "perrresp", "Parity Error Response", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "serr", "SERR#", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "isa", "ISA", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "vga", "VGA", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "vgadec", "VGA 16-bit Decode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "10-bit", "16-bit" } } },
	{ 5, 5, "mabort", "Master Abort", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 6, "secrst", "Secondary Bus Reset", PRDV_HEX },
	{ 7, 7, "fastb2b", "Fast Back-to-Back Transactions", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 8, "pridisc", "Primary Discard Timer", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "2^15 cycles", "2^10 cycles" } } },
	{ 9, 9, "secdisc", "Secondary Discard Timer", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "2^15 cycles", "2^10 cycles" } } },
	{ 10, 10, "disctimer", "Discard Timer Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 11, 11, "discserr", "Discard Timer SERR#", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static pcieadm_unitdef_t pcieadm_unitdef_cache = {
	"byte", 4
};

static pcieadm_unitdef_t pcieadm_unitdef_latreg = { "cycle" };

static const pcieadm_regdef_t pcieadm_regdef_header[] = {
	{ 0, 6, "layout", "Header Layout", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Device", "Bridge", "PC Card" } } },
	{ 7, 7, "mfd", "Multi-Function Device", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_bist[] = {
	{ 0, 3, "code", "Completion Code", PRDV_HEX },
	{ 6, 6, "start", "Start BIST", PRDV_HEX },
	{ 7, 7, "cap", "BIST Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_exprom[] = {
	{ 0, 0, "enable", "Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 3, "valsts", "Validation Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not supported", "in progress",
	    "valid contents, no trust test performed",
	    "valid and trusted contents",
	    "invalid contents",
	    "valid but untrusted contents",
	    "valid contents with warning, no trust test performed",
	    "valid and trusted contents with warning" } } },
	{ 4, 7, "valdet", "Validation Details", PRDV_HEX },
	{ 11, 31, "addr", "Base Address", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 11 } } },
	{ -1, -1, NULL }
};

static pcieadm_strmap_t pcieadm_strmap_ipin[] = {
	{ "none", 0 },
	{ "INTA", PCI_INTA },
	{ "INTB", PCI_INTB },
	{ "INTC", PCI_INTC },
	{ "INTD", PCI_INTD },
	{ NULL }
};


static const pcieadm_cfgspace_print_t pcieadm_cfgspace_type0[] = {
	{ 0x0, 2, "vendor", "Vendor ID", pcieadm_cfgspace_print_vendor },
	{ 0x2, 2, "device", "Device ID", pcieadm_cfgspace_print_device },
	{ 0x4, 2, "command", "Command", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_command },
	{ 0x6, 2, "status", "Status", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_status },
	{ 0x8, 1, "revision", "Revision ID", pcieadm_cfgspace_print_hex },
	{ 0x9, 3, "class", "Class Code", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_class },
	{ 0xc, 1, "cache", "Cache Line Size", pcieadm_cfgspace_print_unit,
	    &pcieadm_unitdef_cache },
	{ 0xd, 1, "latency", "Latency Timer", pcieadm_cfgspace_print_unit,
	    &pcieadm_unitdef_latreg },
	{ 0xe, 1, "type", "Header Type", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_header },
	{ 0xf, 1, "bist", "BIST", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_bist },
	{ 0x10, 24, "bar", "Base Address Register",
	    pcieadm_cfgspace_print_bars },
	{ 0x28, 4, "cis", "Cardbus CIS Pointer", pcieadm_cfgspace_print_hex },
	{ 0x2c, 2, "subvid", "Subsystem Vendor ID",
	    pcieadm_cfgspace_print_subid },
	{ 0x2e, 2, "subdev", "Subsystem Device ID",
	    pcieadm_cfgspace_print_subid },
	{ 0x30, 4, "rom", "Expansion ROM", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_exprom },
	{ 0x34, 1, "cap", "Capabilities Pointer", pcieadm_cfgspace_print_hex },
	{ 0x3c, 1, "iline", "Interrupt Line", pcieadm_cfgspace_print_hex },
	{ 0x3d, 1, "ipin", "Interrupt Pin", pcieadm_cfgspace_print_strmap,
	    pcieadm_strmap_ipin },
	{ 0x3e, 1, "gnt", "Min_Gnt", pcieadm_cfgspace_print_hex },
	{ 0x3f, 1, "lat", "Min_Lat", pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cfgspace_type1[] = {
	{ 0x0, 2, "vendor", "Vendor ID", pcieadm_cfgspace_print_vendor },
	{ 0x2, 2, "device", "Device ID", pcieadm_cfgspace_print_device },
	{ 0x4, 2, "command", "Command", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_command },
	{ 0x6, 2, "status", "Status", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_status },
	{ 0x8, 1, "revision", "Revision ID", pcieadm_cfgspace_print_hex },
	{ 0x9, 3, "class", "Class Code", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_class },
	{ 0xc, 1, "cache", "Cache Line Size", pcieadm_cfgspace_print_unit,
	    &pcieadm_unitdef_cache },
	{ 0xd, 1, "latency", "Latency Timer", pcieadm_cfgspace_print_unit,
	    &pcieadm_unitdef_latreg },
	{ 0xe, 1, "type", "Header Type", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_header },
	{ 0xf, 1, "bist", "BIST", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_bist },
	{ 0x10, 8, "bar", "Base Address Register",
	    pcieadm_cfgspace_print_bars },
	{ PCI_BCNF_PRIBUS, 1, "pribus", "Primary Bus Number",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_SECBUS, 1, "secbus", "Secondary Bus Number",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_SUBBUS, 1, "subbus", "Subordinate Bus Number",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_LATENCY_TIMER, 1, "latency2", "Secondary Latency timer",
	    pcieadm_cfgspace_print_unit, &pcieadm_unitdef_latreg },
	{ PCI_BCNF_IO_BASE_LOW, 1, "iobase", "I/O Base Low",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridge_iobase },
	{ PCI_BCNF_IO_LIMIT_LOW, 1, "iolimit", "I/O Limit Low",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridge_iolim },
	{ PCI_BCNF_SEC_STATUS, 2, "status2", "Secondary Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridgests },
	{ PCI_BCNF_MEM_BASE, 2, "membase", "Memory Base",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridge_membase },
	{ PCI_BCNF_MEM_LIMIT, 2, "memlimit", "Memory Limit",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridge_memlim },
	{ PCI_BCNF_PF_BASE_LOW, 2, "pfbase", "Prefetchable Memory Base",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridge_pfbase },
	{ PCI_BCNF_PF_LIMIT_LOW, 2, "pflimit", "Prefetchable Memory Limit",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridge_pflim },
	{ PCI_BCNF_PF_BASE_HIGH, 4, "pfbasehi",
	    "Prefetchable Base Upper 32 bits",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_PF_LIMIT_HIGH, 4, "pflimihi",
	    "Prefetchable Limit Upper 32 bits",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_IO_BASE_HI, 2, "iobasehi", "I/O Base Upper 16 bits",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_IO_LIMIT_HI, 2, "iolimithi", "I/O Limit Upper 16 bits",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_CAP_PTR, 1, "cap", "Capabilities Pointer",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_ROM, 4, "rom", "Expansion ROM",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_exprom },
	{ PCI_BCNF_ILINE, 1, "iline", "Interrupt Line",
	    pcieadm_cfgspace_print_hex },
	{ PCI_BCNF_IPIN, 1, "ipin", "Interrupt Pin",
	    pcieadm_cfgspace_print_strmap, pcieadm_strmap_ipin },
	{ PCI_BCNF_BCNTRL, 2, "bctl", "Bridge Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_bridge_ctl },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cfgspace_unknown[] = {
	{ 0x0, 2, "vendor", "Vendor ID", pcieadm_cfgspace_print_vendor },
	{ 0x2, 2, "device", "Device ID", pcieadm_cfgspace_print_device },
	{ 0x8, 1, "revision", "Revision ID", pcieadm_cfgspace_print_hex },
	{ 0xe, 1, "type", "Header Type", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_header },
	{ -1, -1, NULL }
};

/*
 * Power Management Capability Version 3. Note versions two and three seem to be
 * the same, but are used to indicate compliance to different revisions of the
 * PCI power management specification.
 */
static const pcieadm_regdef_t pcieadm_regdef_pmcap[] = {
	{ 0, 2, "vers", "Version", PRDV_HEX },
	{ 3, 3, "clock", "PME Clock", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not required", "required" } } },
	{ 4, 4, "irrd0", "Immediate Readiness on Return to D0", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 5, 5, "dsi", "Device Specific Initialization", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 6, 8, "auxcur", "Auxiliary Current", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "0", "55 mA", "100 mA", "160 mA",
	    "220 mA", "270 mA", "320 mA", "375 mA" } } },
	{ 9, 9, "d1", "D1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 10, 10, "d2", "D2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 11, 15, "pme", "PME Support", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "D0", "D1", "D2", "D3hot",
	    "D3cold" } } },
	{ -1, -1, NULL }
};


static const pcieadm_cfgspace_print_t pcieadm_cap_pcipm_v3[] = {
	{ PCI_PMCAP, 2, "pmcap", "Power Management Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pmcap },
	{ -1, -1, NULL }
};

/*
 * PCI Bridge Subsystem Capability
 */
static const pcieadm_cfgspace_print_t pcieadm_cap_bridge_subsys[] = {
	{ 0x4, 2, "subvid", "Subsystem Vendor ID", pcieadm_cfgspace_print_hex },
	{ 0x6, 2, "subdev", "Subsystem Device ID", pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

/*
 * MSI Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_msictrl[] = {
	{ 0, 0, "enable", "MSI Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 3, "mmsgcap", "Multiple Message Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1 vector", "2 vectors",
	    "4 vectors", "8 vectors", "16 vectors", "32 vectors" } } },
	{ 4, 6, "mmsgen", "Multiple Message Enabled", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1 vector", "2 vectors",
	    "4 vectors", "8 vectors", "16 vectors", "32 vectors" } } },
	{ 7, 7, "addr64", "64-bit Address Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "pvm", "Per-Vector Masking Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 9, 9, "extmdcap", "Extended Message Data Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 10, 10, "extmden", "extended Message Data Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_msi_32[] = {
	{ PCI_MSI_CTRL, 2, "ctrl", "Message Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msictrl },
	{ PCI_MSI_ADDR_OFFSET, 4, "addr", "Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_32BIT_DATA, 2, "data", "Message Data",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_msi_32ext[] = {
	{ PCI_MSI_CTRL, 2, "ctrl", "Message Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msictrl },
	{ PCI_MSI_ADDR_OFFSET, 4, "addr", "Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_32BIT_DATA, 2, "data", "Message Data",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_32BIT_EXTDATA, 2, "extdata", "Extended Message Data",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_msi_32pvm[] = {
	{ PCI_MSI_CTRL, 2, "ctrl", "Message Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msictrl },
	{ PCI_MSI_ADDR_OFFSET, 4, "addr", "Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_32BIT_DATA, 2, "data", "Message Data",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_32BIT_EXTDATA, 2, "extdata", "Extended Message Data",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_32BIT_MASK, 4, "mask", "Mask Bits",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_32BIT_PENDING, 4, "pend", "Pending Bits",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_msi_64[] = {
	{ PCI_MSI_CTRL, 2, "ctrl", "Message Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msictrl },
	{ PCI_MSI_ADDR_OFFSET, 4, "addr", "Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_ADDR, 4, "upadd", "Upper Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_DATA, 2, "data", "Message Data",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_msi_64ext[] = {
	{ PCI_MSI_CTRL, 2, "ctrl", "Message Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msictrl },
	{ PCI_MSI_ADDR_OFFSET, 4, "addr", "Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_ADDR, 4, "upadd", "Upper Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_DATA, 2, "data", "Message Data",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_EXTDATA, 2, "extdata", "Extended Message Data",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_msi_64pvm[] = {
	{ PCI_MSI_CTRL, 2, "ctrl", "Message Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msictrl },
	{ PCI_MSI_ADDR_OFFSET, 4, "addr", "Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_ADDR, 4, "upadd", "Upper Message Address",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_DATA, 2, "data", "Message Data",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_EXTDATA, 2, "extdata", "Extended Message Data",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_MASKBITS, 4, "mask", "Mask Bits",
	    pcieadm_cfgspace_print_hex },
	{ PCI_MSI_64BIT_PENDING, 4, "pend", "Pending Bits",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

/*
 * MSI-X Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_msixctrl[] = {
	{ 0, 10, "size", "Table Size", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 0, 1 } } },
	{ 14, 14, "mask", "Function Mask", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unmasked", "masked" } } },
	{ 15, 15, "enable", "MSI-X Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_msixtable[] = {
	{ 0, 2, "bir", "Table BIR", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "BAR 0", "BAR 1", "BAR 2", "BAR 3",
	    "BAR 4", "BAR 5" } } },
	{ 3, 31, "offset", "Table Offset", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 3 } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_msixpba[] = {
	{ 0, 2, "bir", "PBA BIR", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "BAR 0", "BAR 1", "BAR 2", "BAR 3",
	    "BAR 4", "BAR 5" } } },
	{ 3, 31, "offset", "PBA Offset", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 3 } } },
	{ -1, -1, NULL }
};


static const pcieadm_cfgspace_print_t pcieadm_cap_msix[] = {
	{ PCI_MSIX_CTRL, 2, "ctrl", "Control Register",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msixctrl },
	{ PCI_MSIX_TBL_OFFSET, 4, "table", "Table Offset",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msixtable },
	{ PCI_MSIX_PBA_OFFSET, 4, "pba", "PBA Offset",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_msixpba },
	{ -1, -1, NULL }
};

/*
 * PCI Express Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_pcie_cap[] = {
	{ 0, 3, "vers", "Version", PRDV_HEX },
	{ 4, 7, "type", "Device/Port Type", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "PCIe Endpoint",
	    "Legacy PCIe Endpoint", NULL, NULL,
	    "Root Port of PCIe Root Complex",
	    "Upstream Port of PCIe Switch",
	    "Downstream Port of PCIe Switch",
	    "PCIe to PCI/PCI-X Bridge",
	    "PCI/PCI-x to PCIe Bridge",
	    "RCiEP",
	    "Root Complex Event Collector" } } },
	{ 8, 8, "slot", "Slot Implemented", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "No", "Yes" } } },
	{ 9, 13, "intno", "Interrupt Message Number", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_devcap[] = {
	{ 0, 2, "mps", "Max Payload Size Supported", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "128 bytes", "256 bytes",
	    "512 bytes", "1024 bytes", "2048 bytes", "4096 bytes" } } },
	{ 3, 4, "pfunc", "Phantom Functions Supported", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "No", "1-bit", "2-bits",
	    "3-bits" } } },
	{ 5, 5, "exttag", "Extended Tag Field", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "5-bit", "8-bit" } } },
	{ 6, 8, "l0slat", "L0s Acceptable Latency", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "64 ns", "128 ns", "256 ns",
	    "512 ns", "1 us", "2 us", "4 us", "No limit" } } },
	{ 9, 11, "l1lat", "L1 Acceptable Latency", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1 us", "2 us", "4 us", "8 us",
	    "16 us", "32 us", "64 us", "No limit" } } },
	{ 15, 15, "rber", "Role Based Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 16, 16, "errcor", "ERR_COR Subclass", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 18, 25, "csplv", "Captured Slot Power Limit", PRDV_HEX },
	{ 26, 27, "cspls", "Captured Slot Power Limit Scale", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1.0x", "0.1x", "0.01x",
	    "0.001x" } } },
	{ 28, 28, "flr", "Function Level Reset", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_devctl[] = {
	{ 0, 0, "corerr", "Correctable Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "nferr", "Non-Fatal Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "ferr", "Fatal Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "unsupreq", "Unsupported Request Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "relord", "Relaxed Ordering", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 7, "mps", "Max Payload Size", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "128 bytes", "256 bytes",
	    "512 bytes", "1024 bytes", "2048 bytes", "4096 bytes" } } },
	{ 8, 8, "exttag", "Extended Tag Field", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 9, 9, "pfunc", "Phantom Functions", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 9, 9, "auxpm", "Aux Power PM", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 11, 11, "nosnoop", "No Snoop", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 12, 14, "mrrs", "Max Read Request Size", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "128 bytes", "256 bytes",
	    "512 bytes", "1024 bytes", "2048 bytes", "4096 bytes" } } },
	{ 15, 15, "bcrflr", "Bridge Configuration Retry / Function Level Reset",
	    PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_devsts[] = {
	{ 0, 0, "corerr", "Correctable Error Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 1, 1, "nferr", "Non-Fatal Error Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 2, 2, "ferr", "Fatal Error Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 3, 3, "unsupreq", "Unsupported Request Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 4, 4, "auxpm", "AUX Power Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 5, 5, "txpend", "Transactions Pending", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 6, 6, "eprd", "Emergency Power Reduction Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_linkcap[] = {
	{ 0, 3, "maxspeed", "Maximum Link Speed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { NULL, "2.5 GT/s", "5.0 GT/s",
	    "8.0 GT/s", "16.0 GT/s", "32.0 GT/s", "64.0 GT/s" } } },
	{ 4, 9, "maxwidth", "Maximum Link Width", PRDV_HEX },
	{ 10, 11, "aspm", "ASPM Support", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "None", "L0s", "L1", "L0s/L1" } } },
	{ 12, 14, "l0slat", "L0s Exit Latency", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "<64ns", "64-128ns", "128-256ns",
	    "256-512ns", "512ns-1us", "1-2us", "2-4us", ">4us" } } },
	{ 15, 17, "l1lat", "L1 Exit Latency", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "<1us", "1-2us", "2-4us", "4-8us",
	    "8-16us", "16-32us" "32-64us", ">64us" } } },
	{ 18, 18, "clockpm", "Clock Power Management", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 19, 19, "supdown", "Surprise Down Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 20, 20, "dlact", "Data Link Layer Active Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 21, 21, "linkbw", "Link Bandwidth Notification Capability",
	    PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 22, 22, "aspmcomp", "ASPM Optionality Compliance", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not compliant", "compliant" } } },
	{ 24, 31, "portno", "Port Number", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_linkctl[] = {
	{ 0, 1, "aspmctl", "ASPM Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "None", "L0s", "L1", "L0s/L1" } } },
	{ 3, 3, "rcb", "Read Completion Boundary", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "64 byte", "128 byte" } } },
	{ 4, 4, "disable", "Link Disable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not force disabled",
	    "force disabled" } } },
	{ 5, 5, "retrain", "Retrain Link", PRDV_HEX },
	{ 6, 6, "ccc", "Common Clock Configuration", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "asynchronous", "common" } } },
	{ 7, 7, "extsync", "Extended Sync", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 8, "clkpm", "Clock Power Management", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 9, 9, "hwawd", "Hardware Autonomous Width", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "enabled", "disabled" } } },
	{ 10, 10, "linkbwint", "Link Bandwidth Management Interrupt",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "disabled",
	    "enabled" } } },
	{ 11, 11, "linkabwint", "Link Autonomous Bandwidth Interrupt",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "disabled",
	    "enabled" } } },
	{ 14, 15, "drs", "DRS Signaling Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not reported", "Interrupt enabled",
	    "DRS->FRS enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_linksts[] = {
	{ 0, 3, "speed", "Link Speed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { NULL, "2.5 GT/s", "5.0 GT/s",
	    "8.0 GT/s", "16.0 GT/s", "32.0 GT/s", "64.0 GT/s" } } },
	{ 4, 9, "width", "Link Width", PRDV_HEX },
	{ 11, 11, "training", "Link Training", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 12, 12, "slotclk", "Slot Clock Configuration", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "asynchronous", "common" } } },
	{ 13, 13, "dllact", "Data Link Layer Link Active", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 14, 14, "linkbw", "Link Bandwidth Management Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no change", "change occurred" } } },
	{ 15, 15, "linkabw", "Link Autonomous Bandwidth Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no change", "change occurred" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_slotcap[] = {
	{ 0, 0, "attnbtn", "Attention Button Present", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 1, 1, "pwrctrl", "Power Controller Present", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 2, 2, "mrlsen", "MRL Sensor Present", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 3, 3, "attnind", "Attention Indicator Present", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 4, 4, "pwrind", "Power Indicator Present", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 5, 5, "hpsup", "Hot-Plug Surprise", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 6, 6, "hpcap", "Hot-Plug Capable ", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 7, 14, "slotplv", "Slot Power Limit Value", PRDV_HEX },
	{ 15, 16, "slotpls", "Slot Power Limit Scale", PRDV_HEX },
	{ 17, 17, "emi", "Electromechanical Interlock Present", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 18, 18, "ncc", "No Command Completed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 19, 31, "slotno", "Physical Slot Number", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_slotctl[] = {
	{ 0, 0, "attnbtn", "Attention Button Pressed Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "pwrflt", "Power Fault Detected Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "mrlchg", "MRL Sensor Changed Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "preschg", "Presence Detect Changed Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "ccmpltint", "Command Complete Interrupt", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 5, "hpi", "Hot Plug Interrupt Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 7, "attnind", "Attention Indicator Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { NULL, "on", "blink", "off" } } },
	{ 8, 9, "pwrin", "Power Indicator Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { NULL, "on", "blink", "off" } } },
	{ 10, 10, "pwrctrl", "Power Controller Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "power on", "power off" } } },
	{ 11, 11, "emi", "Electromechanical Interlock Control", PRDV_HEX },
	{ 12, 12, "dll", "Data Link Layer State Changed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 13, 13, "autopowdis", "Auto Slot Power Limit", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "enabled", "disabled" } } },
	{ 14, 14, "ibpddis", "In-Band PD", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "enabled", "disabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_slotsts[] = {
	{ 0, 0, "attnbtn", "Attention Button Pressed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 1, 1, "pwrflt", "Power Fault Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 2, 2, "mrlchg", "MRL Sensor Changed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 3, 3, "preschg", "Presence Detect Changed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 4, 4, "ccmplt", "Command Complete", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 5, 5, "mrlsen", "MRL Sensor State", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "closed", "open" } } },
	{ 6, 6, "presdet", "Presence Detect State", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not present", "present" } } },
	{ 7, 7, "emi", "Electromechanical Interlock", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disengaged", "engaged" } } },
	{ 8, 8, "dll", "Data Link Layer State Changed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_rootcap[] = {
	{ 0, 0, "syscorerr", "System Error on Correctable Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "sysnonftl", "System Error on Non-Fatal Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "sysfatal", "System Error on Fatal Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "pmeie", "PME Interrupt", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4,  "crssw", "CRS Software Visibility", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_rootctl[] = {
	{ 0, 0, "crssw", "CRS Software Visibility", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_rootsts[] = {
	{ 0, 15, "pmereqid", "PME Requester ID", PRDV_HEX },
	{ 16, 16, "pmests", "PME Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "deasserted", "asserted" } } },
	{ 17, 17, "pmepend", "PME Pending", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_devcap2[] = {
	{ 0, 3, "cmpto", "Completion Timeout Ranges Supported", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "50us-10ms", "10ms-250ms",
	    "250ms-4s", "4s-64s" } } },
	{ 4, 4, "cmptodis", "Completion Timeout Disable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 5, 5, "ari", "ARI Forwarding", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 6, 6, "atomroute", "AtomicOp Routing", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 7, 7, "atom32", "32-bit AtomicOp Completer", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "atom64", "64-bit AtomicOp Completer", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 9, 9, "cas128", "128-bit CAS Completer", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 10, 10, "norelord", "No Ro-enabld PR-PR Passing", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 11, 11, "ltr", "LTR Mechanism", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 12, 13, "tph", "TPH Completer", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "TPH supported",
	    NULL, "TPH and Extended TPH supported" } } },
	{ 14, 15, "lncls", "LN System CLS", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported",
	    "LN with 64-byte cachelines", "LN with 128-byte cachelines" } } },
	{ 16, 16, "tag10comp", "10-bit Tag Completer", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 17, 17, "tag10req", "10-bit Tag Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 18, 19, "obff", "OBFF", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "Message Signaling",
	    "WAKE# Signaling", "WAKE# and Message Signaling" } } },
	{ 20, 20, "extfmt", "Extended Fmt Field Supported", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 21, 21, "eetlp", "End-End TLP Prefix Supported", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 22, 23, "maxeetlp", "Max End-End TLP Prefixes", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "4", "1", "2", "3" } } },
	{ 24, 25, "empr", "Emergency Power Reduction", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported",
	    "supported, device-specific",
	    "supported, from factor or device-specific" } } },
	{ 21, 21, "emprinit",
	    "Emergency Power Reduction Initialization Required", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 31, 31, "frs", "Function Readiness Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_devctl2[] = {
	{ 0, 3, "cmpto", "Completion Timeout", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "50us-50ms", "50us-100us",
	    "1ms-10ms", NULL, NULL, "16ms-55ms", "65ms-210ms", NULL, NULL,
	    "260ms-900ms", "1s-3.5s", NULL, NULL, "4s-13s", "17s-64s" } } },
	{ 4, 4, "cmptodis", "Completion Timeout Disabled", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not disabled", "disabled" } } },
	{ 5, 5, "ari", "ARI Forwarding", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 6, "atomreq", "AtomicOp Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 7, 7, "atomblock", "AtomicOp Egress Blocking", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unblocked", "blocked" } } },
	{ 8, 8, "idoreq", "ID-Based Ordering Request", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 9, 9, "idocomp", "ID-Based Ordering Completion", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 10, 10, "ltr", "LTR Mechanism", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 11, 11, "empowred", "Emergency Power Reduction", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not requested", "requested" } } },
	{ 12, 12, "tag10req", "10-bit Tag Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 13, 14, "obff", "OBFF", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "message signaling - A",
	    "message signaling - B", "WAKE# signaling" } } },
	{ 15, 15, "eetlpblk", "End-End TLP Prefix Blocking", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unblocked", "blocked" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_devsts2[] = {
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_linkcap2[] = {
	{ 1, 7, "supspeeds", "Supported Link Speeds", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "2.5 GT/s", "5.0 GT/s", "8.0 GT/s",
	    "16.0 GT/s", "32.0 GT/s", "64.0 GT/s" } } },
	{ 8, 8, "crosslink", "Crosslink", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 9, 15, "skposgen", "Lower SKP OS Generation Supported Speeds Vector",
	    PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "2.5 GT/s", "5.0 GT/s", "8.0 GT/s",
	    "16.0 GT/s", "32.0 GT/s", "64.0 GT/s" } } },
	{ 16, 22, "skposrecv", "Lower SKP OS Reception Supported Speeds Vector",
	    PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "2.5 GT/s", "5.0 GT/s", "8.0 GT/s",
	    "16.0 GT/s", "32.0 GT/s", "64.0 GT/s" } } },
	{ 23, 23, "retimedet", "Retimer Presence Detect Supported", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 24, 24, "retime2det", "Two Retimers Presence Detect Supported",
	    PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 31, 31, "drs", "Device Readiness Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_linkctl2[] = {
	{ 0, 3, "targspeed", "Target Link Speed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { NULL, "2.5 GT/s", "5.0 GT/s",
	    "8.0 GT/s", "16.0 GT/s", "32.0 GT/s", "64.0 GT/s" } } },
	{ 4, 4, "comp", "Enter Compliance", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 5, 5, "hwautosp", "Hardware Autonomous Speed Disable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not disabled", "disabled" } } },
	{ 6, 6, "seldeemph", "Selectable De-emphasis", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "-6 dB", "-3.5 dB" } } },
	{ 7, 9, "txmarg", "TX Margin", PRDV_HEX },
	{ 10, 10, "modcomp", "Enter Modified Compliance", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 11, 11, "compsos", "Compliance SOS",
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 12, 15, "compemph", "Compliance Preset/De-emphasis", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_linksts2[] = {
	{ 0, 0, "curdeemph", "Current De-emphasis Level", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "-6 dB", "-3.5 dB" } } },
	{ 1, 1, "eq8comp", "Equalization 8.0 GT/s Complete", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 2, 2, "eq8p1comp", "Equalization 8.0 GT/s Phase 1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsuccessful", "successful" } } },
	{ 3, 3, "eq8p2comp", "Equalization 8.0 GT/s Phase 2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsuccessful", "successful" } } },
	{ 4, 4, "eq8p3comp", "Equalization 8.0 GT/s Phase 3", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsuccessful", "successful" } } },
	{ 5, 5, "linkeq8req", "Link Equalization Request 8.0 GT/s", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not requested", "requested" } } },
	{ 6, 6, "retimedet", "Retimer Presence Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 7, 7, "retime2det", "Two Retimers Presence Detected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 8, 9, "crosslink", "Crosslink Resolution", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "upstream port",
	    "downstream port", "incomplete" } } },
	{ 12, 14, "dscomppres", "Downstream Component Presence", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "link down - undetermined",
	    "link down - not present", "link down - present", NULL,
	    "link up - present", "link up - present and DRS" } } },
	{ 15, 15, "drsrx", "DRS Message Received", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_slotcap2[] = {
	{ 0, 0, "ibpddis", "In-Band PD Disable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_slotctl2[] = {
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie_slotsts2[] = {
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_pcie_v1_dev[] = {
	{ PCIE_PCIECAP, 2, "cap", "Capability Register",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_cap },
	{ PCIE_DEVCAP, 4, "devcap", "Device Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devcap },
	{ PCIE_DEVSTS, 2, "devsts", "Device Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devsts },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_pcie_v1_link[] = {
	{ PCIE_PCIECAP, 2, "cap", "Capability Register",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_cap },
	{ PCIE_DEVCAP, 4, "devcap", "Device Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devcap },
	{ PCIE_DEVSTS, 2, "devsts", "Device Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devsts },
	{ PCIE_LINKCAP, 4, "linkcap", "Link Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkcap },
	{ PCIE_LINKCTL, 2, "linkctl", "Link Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkctl },
	{ PCIE_LINKSTS, 2, "linksts", "Link Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linksts },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_pcie_v1_slot[] = {
	{ PCIE_PCIECAP, 2, "cap", "Capability Register",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_cap },
	{ PCIE_DEVCAP, 4, "devcap", "Device Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devcap },
	{ PCIE_DEVSTS, 2, "devsts", "Device Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devsts },
	{ PCIE_LINKCAP, 4, "linkcap", "Link Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkcap },
	{ PCIE_LINKCTL, 2, "linkctl", "Link Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkctl },
	{ PCIE_LINKSTS, 2, "linksts", "Link Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linksts },
	{ PCIE_SLOTCAP, 4, "slotcap", "Slot Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotcap },
	{ PCIE_SLOTCTL, 2, "slotctl", "Slot Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotctl },
	{ PCIE_SLOTSTS, 2, "slotsts", "Slot Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotsts },
	{ -1, -1, NULL }
};


static const pcieadm_cfgspace_print_t pcieadm_cap_pcie_v1_all[] = {
	{ PCIE_PCIECAP, 2, "cap", "Capability Register",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_cap },
	{ PCIE_DEVCAP, 4, "devcap", "Device Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devcap },
	{ PCIE_DEVSTS, 2, "devsts", "Device Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devsts },
	{ PCIE_LINKCAP, 4, "linkcap", "Link Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkcap },
	{ PCIE_LINKCTL, 2, "linkctl", "Link Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkctl },
	{ PCIE_LINKSTS, 2, "linksts", "Link Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linksts },
	{ PCIE_SLOTCAP, 4, "slotcap", "Slot Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotcap },
	{ PCIE_SLOTCTL, 2, "slotctl", "Slot Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotctl },
	{ PCIE_SLOTSTS, 2, "slotsts", "Slot Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotsts },
	{ PCIE_ROOTCTL, 2, "rootctl", "Root control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_rootctl },
	{ PCIE_ROOTCAP, 2, "rootcap", "Root Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_rootcap },
	{ PCIE_ROOTSTS, 4, "rootsts", "Root Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_rootsts },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_pcie_v2[] = {
	{ PCIE_PCIECAP, 2, "cap", "Capability Register",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_cap },
	{ PCIE_DEVCAP, 4, "devcap", "Device Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devcap },
	{ PCIE_DEVCTL, 2, "devctl", "Device Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devctl },
	{ PCIE_DEVSTS, 2, "devsts", "Device Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devsts },
	{ PCIE_LINKCAP, 4, "linkcap", "Link Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkcap },
	{ PCIE_LINKCTL, 2, "linkctl", "Link Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkctl },
	{ PCIE_LINKSTS, 2, "linksts", "Link Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linksts },
	{ PCIE_SLOTCAP, 4, "slotcap", "Slot Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotcap },
	{ PCIE_SLOTCTL, 2, "slotctl", "Slot Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotctl },
	{ PCIE_SLOTSTS, 2, "slotsts", "Slot Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotsts },
	{ PCIE_ROOTCTL, 2, "rootctl", "Root Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_rootctl },
	{ PCIE_ROOTCAP, 2, "rootcap", "Root Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_rootcap },
	{ PCIE_ROOTSTS, 4, "rootsts", "Root Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_rootsts },
	{ PCIE_DEVCAP2, 4, "devcap2", "Device Capabilities 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devcap2 },
	{ PCIE_DEVCTL2, 2, "devctl2", "Device Control 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devctl2 },
	{ PCIE_DEVSTS2, 2, "devsts2", "Device Status 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_devsts2 },
	{ PCIE_LINKCAP2, 4, "linkcap2", "Link Capabilities 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkcap2 },
	{ PCIE_LINKCTL2, 2, "linkctl2", "Link Control 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linkctl2 },
	{ PCIE_LINKSTS2, 2, "linksts2", "Link Status 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_linksts2 },
	{ PCIE_SLOTCAP2, 4, "slotcap2", "Slot Capabilities 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotcap2 },
	{ PCIE_SLOTCTL2, 2, "slotctl2", "Slot Control 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotctl2 },
	{ PCIE_SLOTSTS2, 2, "slotsts2", "Slot Status 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_slotsts2 },
	{ -1, -1, NULL }
};

/*
 * PCIe Extended Capability Header
 */
static const pcieadm_regdef_t pcieadm_regdef_pcie_caphdr[] = {
	{ 0, 15, "capid", "Capability ID", PRDV_HEX },
	{ 16, 19, "version", "Capability Version", PRDV_HEX },
	{ 20, 32, "offset", "Next Capability Offset", PRDV_HEX },
	{ -1, -1, NULL }
};

/*
 * VPD Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_vpd_addr[] = {
	{ 0, 14, "addr", "VPD Address", PRDV_HEX },
	{ 15, 15, "flag", "Flag", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_vpd[] = {
	{ 0x2, 2, "addr", "VPD Address Register",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_vpd_addr },
	{ 0x4, 4, "data", "VPD Data", pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

/*
 * SATA Capability per AHCI 1.3.1
 */
static const pcieadm_regdef_t pcieadm_regdef_sata_cr0[] = {
	{ 0, 3, "minrev", "Minor Revision", PRDV_HEX },
	{ 4, 7, "majrev", "Major Revision", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_sata_cr1[] = {
	{ 0, 3, "bar", "BAR Location", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 2 } } },
	{ 4, 23, "offset", "BAR Offset", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 2 } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_sata[] = {
	{ 0x2, 2, "satacr0", "SATA Capability Register 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sata_cr0 },
	{ 0x4, 4, "satacr1", "SATA Capability Register 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sata_cr1 },
	{ -1, -1, NULL }
};

/*
 * Debug Capability per EHCI
 */
static const pcieadm_regdef_t pcieadm_regdef_debug[] = {
	{ 0, 12, "offset", "BAR Offset", PRDV_HEX },
	{ 13, 15, "bar", "BAR Location ", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { NULL, "BAR 0", "BAR 1", "BAR 2",
	    "BAR 3", "BAR 4", "BAR 5" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_debug[] = {
	{ 0x2, 2, "port", "Debug Port",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_debug },
	{ -1, -1, NULL }
};

/*
 * AER Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_aer_ue[] = {
	{ 4, 4, "dlp", "Data Link Protocol Error", PRDV_HEX },
	{ 5, 5, "sde", "Surprise Down Error", PRDV_HEX },
	{ 12, 12, "ptlp", "Poisoned TLP Received", PRDV_HEX },
	{ 13, 13, "fcp", "Flow Control Protocol Error", PRDV_HEX },
	{ 14, 14, "cto", "Completion Timeout", PRDV_HEX },
	{ 15, 15, "cab", "Completion Abort", PRDV_HEX },
	{ 16, 16, "unco", "Unexpected Completion", PRDV_HEX },
	{ 17, 17, "rxov", "Receiver Overflow", PRDV_HEX },
	{ 18, 18, "maltlp", "Malformed TLP", PRDV_HEX },
	{ 19, 19, "ecrc", "ECRC Error", PRDV_HEX },
	{ 20, 20, "usuprx", "Unsupported Request Error", PRDV_HEX },
	{ 21, 21, "acs", "ACS Violation", PRDV_HEX },
	{ 22, 22, "ueint", "Uncorrectable Internal Error", PRDV_HEX },
	{ 23, 23, "mcbtlp", "MC Blocked TLP", PRDV_HEX },
	{ 24, 24, "atoomeb", "AtomicOp Egress Blocked", PRDV_HEX },
	{ 25, 25, "tlppb", "TLP Prefix Blocked Error", PRDV_HEX },
	{ 26, 26, "ptlpeb", "Poisoned TLP Egress Blocked", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_aer_ce[] = {
	{ 0, 0, "rxerr", "Receiver Error", PRDV_HEX },
	{ 6, 6, "badtlp", "Bad TLP", PRDV_HEX },
	{ 7, 7, "baddllp", "Bad DLLP", PRDV_HEX },
	{ 8, 8, "replayro", "REPLAY_NUM Rollover", PRDV_HEX },
	{ 12, 12, "rtto", "Replay timer Timeout", PRDV_HEX },
	{ 13, 13, "advnfe", "Advisory Non-Fatal Error", PRDV_HEX },
	{ 14, 14, "ceint", "Correctable Internal Error", PRDV_HEX },
	{ 15, 15, "headlov", "Header Log Overflow", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_aer_ctrl[] = {
	{ 0, 4, "feptr", "First Error Pointer", PRDV_HEX },
	{ 5, 5, "ecgencap", "ECRC Generation Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 6, 6, "ecgenen", "ECRC Generation Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 7, 7, "ecchkcap", "ECRC Check Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "ecchken", "ECRC Check Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_aer_rootcom[] = {
	{ 0, 0, "corerr", "Correctable Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "nferr", "Non-Fatal Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "faterr", "Fatal Error Reporting", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_aer_rootsts[] = {
	{ 0, 0, "errcor", "ERR_COR Received", PRDV_HEX },
	{ 1, 1, "merrcor", "Multiple ERR_COR Received", PRDV_HEX },
	{ 2, 2, "errfnf", "ERR_FATAL/NONFATAL Received", PRDV_HEX },
	{ 3, 3, "merrfnf", "Multiple ERR_FATAL/NONFATAL Received", PRDV_HEX },
	{ 4, 4, "fuefat", "First Uncorrectable Fatal", PRDV_HEX },
	{ 5, 5, "nferrrx", "Non-Fatal Error Messages Received", PRDV_HEX },
	{ 6, 6, "faterrx", "Fatal Error Messages Received", PRDV_HEX },
	{ 7, 8, "errcorsc", "ERR_COR Subclass", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "ECS Legacy", "ECS SIG_SFW",
	    "ECS SIG_OS", "ECS Extended" } } },
	{ 27, 31, "inum", "Advanced Error Interrupt Message", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_aer_esi[] = {
	{ 0, 15, "errcorr", "ERR_COR Source", PRDV_HEX },
	{ 16, 31, "errfnf", "ERR_FATAL/NONFATAL Source", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_aer_secue[] = {
	{ 0, 0, "taosc", "Target-Abort on Split Completion", PRDV_HEX },
	{ 1, 1, "maosc", "Master-Abort on Split Completion", PRDV_HEX },
	{ 2, 2, "rxta", "Received Target-Abort", PRDV_HEX },
	{ 3, 3, "rxma", "Received Master-Abort", PRDV_HEX },
	{ 5, 5, "unsce", "Unexpected Split Completion Error", PRDV_HEX },
	{ 6, 6, "uescmd", "Uncorrectable Split Completion Message Data Error",
	    PRDV_HEX },
	{ 7, 7, "uede", "Uncorrectable Data Error", PRDV_HEX },
	{ 8, 8, "ueattre", "Uncorrectable Attribute Error", PRDV_HEX },
	{ 9, 9, "ueaddre", "Uncorrectable Address Error", PRDV_HEX },
	{ 10, 10, "dtdte", "Delayed Transaction Discard Timer Expired",
	    PRDV_HEX },
	{ 11, 11, "perr", "PERR# Assertion", PRDV_HEX },
	{ 12, 12, "serr", "SERR# Assertion", PRDV_HEX },
	{ 13, 13, "internal", "Internal Bridge Error", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_aer_secctl[] = {
	{ 0, 4, "feptr", "Secondary Uncorrectable First Error Pointer",
	    PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_aer_v1[] = {
	{ PCIE_AER_CAP, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ PCIE_AER_UCE_STS, 4, "uestatus", "Uncorrectable Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_UCE_MASK, 4, "uemask", "Uncorrectable Error Mask",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_UCE_SERV, 4, "ueserv", "Uncorrectable Error Severity",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_CE_STS, 4, "cestatus", "Correctable Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ce },
	{ PCIE_AER_CE_MASK, 4, "cemask", "Correctable Error Mask",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ce },
	{ PCIE_AER_CTL, 4, "ctrl", "Advanced Error Capabilities and Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ctrl },
	{ PCIE_AER_HDR_LOG + 4, 4, "hl0", "Header Log 0",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 8, 4, "hl1", "Header Log 1",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 12, 4, "hl2", "Header Log 2",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 12, 4, "hl3", "Header Log 3",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_RE_CMD, 4, "rootcmd", "Root Error Command",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_rootcom },
	{ PCIE_AER_RE_STS, 4, "rootsts", "Root Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_rootsts },
	{ PCIE_AER_CE_SRC_ID, 4, "esi", "Error Source Identification",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_esi },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_aer_v2[] = {
	{ PCIE_AER_CAP, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ PCIE_AER_UCE_STS, 4, "uestatus", "Uncorrectable Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_UCE_MASK, 4, "uemask", "Uncorrectable Error Mask",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_UCE_SERV, 4, "ueserv", "Uncorrectable Error Severity",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_CE_STS, 4, "cestatus", "Correctable Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ce },
	{ PCIE_AER_CE_MASK, 4, "cemask", "Correctable Error Mask",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ce },
	{ PCIE_AER_CTL, 4, "ctrl", "Advanced Error Capabilities and Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ctrl },
	{ PCIE_AER_HDR_LOG + 4, 4, "hl0", "Header Log 0",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 8, 4, "hl1", "Header Log 1",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 12, 4, "hl2", "Header Log 2",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 12, 4, "hl3", "Header Log 3",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_RE_CMD, 4, "rootcmd", "Root Error Command",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_rootcom },
	{ PCIE_AER_RE_STS, 4, "rootsts", "Root Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_rootsts },
	{ PCIE_AER_TLP_PRE_LOG, 4, "tlplog0", "TLP Prefix Log 0",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_TLP_PRE_LOG + 4, 4, "tlplog1", "TLP Prefix Log 1",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_TLP_PRE_LOG + 8, 4, "tlplog2", "TLP Prefix Log 2",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_TLP_PRE_LOG + 12, 4, "tlplog3", "TLP Prefix Log 3",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_aer_bridge[] = {
	{ PCIE_AER_CAP, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ PCIE_AER_UCE_STS, 4, "uestatus", "Uncorrectable Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_UCE_MASK, 4, "uemask", "Uncorrectable Error Mask",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_UCE_SERV, 4, "ueserv", "Uncorrectable Error Severity",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ue },
	{ PCIE_AER_CE_STS, 4, "cestatus", "Correctable Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ce },
	{ PCIE_AER_CE_MASK, 4, "cemask", "Correctable Error Mask",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ce },
	{ PCIE_AER_CTL, 4, "ctrl", "Advanced Error Capabilities and Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_ctrl },
	{ PCIE_AER_HDR_LOG + 4, 4, "hl0", "Header Log 0",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 8, 4, "hl1", "Header Log 1",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 12, 4, "hl2", "Header Log 2",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_HDR_LOG + 12, 4, "hl3", "Header Log 3",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_RE_CMD, 4, "rootcmd", "Root Error Command",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_rootcom },
	{ PCIE_AER_RE_STS, 4, "rootsts", "Root Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_rootsts },
	{ PCIE_AER_CE_SRC_ID, 4, "esi", "Error Source Identification",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_esi },
	{ PCIE_AER_SUCE_STS, 4, "secuests",
	    "Secondary Uncorrectable Error Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_secue },
	{ PCIE_AER_SUCE_MASK, 4, "secuests",
	    "Secondary Uncorrectable Error Mask",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_secue },
	{ PCIE_AER_SUCE_SERV, 4, "secuests",
	    "Secondary Uncorrectable Error Severity",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_secue },
	{ PCIE_AER_SCTL, 4, "secctrl",
	    "Secondary Error Capabilityes and Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_aer_secctl },
	{ PCIE_AER_SHDR_LOG, 4, "shl0", "Secondary Header Log 0",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_SHDR_LOG + 4, 4, "shl1", "Secondary Header Log 1",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_SHDR_LOG + 8, 4, "shl1", "Secondary Header Log 2",
	    pcieadm_cfgspace_print_hex },
	{ PCIE_AER_SHDR_LOG + 12, 4, "shl1", "Secondary Header Log 3",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

/*
 * Secondary PCI Express Extended Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_pcie2_linkctl3[] = {
	{ 0, 0, "peq", "Perform Equalization", PRDV_HEX },
	{ 1, 1, "leqrie", "Link Equalization Request Interrupt Enable",
	    PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 9, 15, "elskpos", "Enable Lower SKP OS Generation Vector",
	    PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "2.5 GT/s", "5.0 GT/s", "8.0 GT/s",
	    "16.0 GT/s", "32.0 GT/s" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcie2_linkeq[] = {
	{ 0, 3, "dstxpre", "Downstream Port 8.0 GT/s Transmitter Preset",
	    PRDV_HEX },
	{ 4, 6, "dstxhint", "Downstream Port 8.0 GT/s Receiver Hint",
	    PRDV_HEX },
	{ 8, 11, "ustxpre", "Upstream Port 8.0 GT/s Transmitter Preset",
	    PRDV_HEX },
	{ 12, 14, "ustxhint", "Upstream Port 8.0 GT/s Receiver Hint",
	    PRDV_HEX },
	{ -1, -1, NULL }
};

static void
pcieadm_cfgspace_print_laneq(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	if (walkp->pcw_nlanes == 0) {
		warnx("failed to capture lane count, but somehow have "
		    "secondary PCIe cap");
		return;
	}

	for (uint_t i = 0; i < walkp->pcw_nlanes; i++) {
		char eqshort[32], eqhuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(eqshort, sizeof (eqshort), "lane%u", i);
		(void) snprintf(eqhuman, sizeof (eqhuman), "Lane %u EQ Control",
		    i);
		p.pcp_off = print->pcp_off + i * 2;
		p.pcp_len = 2;
		p.pcp_short = eqshort;
		p.pcp_human = eqhuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_pcie2_linkeq;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_pcie2[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "linkctl3", "Link Control 3",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie2_linkctl3 },
	{ 0x8, 4, "laneerr", "Lane Error Status", pcieadm_cfgspace_print_hex },
	{ 0xc, 2, "eqctl", "Lane Equalization Control",
	    pcieadm_cfgspace_print_laneq },
	{ -1, -1, NULL }
};

/*
 * Access Control Services
 */
static const pcieadm_regdef_t pcieadm_regdef_acs_cap[] = {
	{ 0, 0, "srcvd", "ACS Source Validation", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "tranblk", "ACS Transaction Blocking", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 2, 2, "p2prr", "ACS P2P Request Redirect", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 3, 3, "p2pcr", "ACS P2P Completion Redirect", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 4, 4, "upfwd", "ACS Upstream Forwarding", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 5, 5, "p2pegctl", "ACS P2P Egress Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 6, 6, "dtp2p", "ACS Direct Translated P2P", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 7, 7, "enhcap", "ACS Enhanced Capability", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 15, "ecvsz", "Egress Control Vector Size", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_acs_ctl[] = {
	{ 0, 0, "srcvd", "ACS Source Validation", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "tranblk", "ACS Transaction Blocking", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "p2prr", "ACS P2P Request Redirect", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "p2pcr", "ACS P2P Completion Redirect", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "upfwd", "ACS Upstream Forwarding", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 5, "p2pegctl", "ACS P2P Egress Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 6, "dtp2p", "ACS Direct Translated P2P", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 7, 7, "iorb", "ACS I/O Request Blocking", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 9, "dspmta", "ACS DSP Memory Target Access Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Direct Request access",
	    "Request blocking", "Request redirect" } } },
	{ 10, 11, "uspmta", "ACS USP Memory Target Access Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Direct Request access",
	    "Request blocking", "Request redirect" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_acs[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "cap", "ACS Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_acs_cap },
	{ 0x6, 2, "ctl", "ACS Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_acs_ctl },
	{ 0x8, 4, "ecv", "Egress Control Vector", pcieadm_cfgspace_print_ecv },
	{ -1, -1, NULL }
};

/*
 * L1 PM Substates
 */
static const pcieadm_regdef_t pcieadm_regdef_l1pm_cap[] = {
	{ 0, 0, "pcil1.2", "PCI-PM L1.2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "pcil1.1", "PCI-PM L1.1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 2, 2, "aspml1.2", "ASPM L1.2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 3, 3, "aspml1.1", "ASPM L1.1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 4, 4, "l1pmsub", "L1 PM Substates", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 5, 5, "linkact", "Link Activation", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 15, "pcmrt", "Port Common_Mode_Restore_Time", PRDV_HEX },
	{ 16, 17, "poscale", "Port T_POWER_ON Scale", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "2 us", "10 us", "100 us" } } },
	{ 19, 23, "portpo", "Port T_POWER_ON Value", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_l1pm_ctl1[] = {
	{ 0, 0, "pcil1.2", "PCI-PM L1.2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "pcil1.1", "PCI-PM L1.1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "aspml1.2", "ASPM L1.2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "aspml1.1", "ASPM L1.1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "laie", "Link Activation Interrupt Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 5, "lactl", "Link Activation Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 15, "cmrt", "Common_Mode_Restore_Time", PRDV_HEX },
	{ 16, 25, "ltrl1.2", "LTR L1.2 Threshold Value", PRDV_HEX },
	{ 29, 31, "ltrl1.2s", "LTR L1.2 Threshold Scale", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1 ns", "32 ns", "1024 ns",
	    "32,768 ns", "1,048,576 ns", "33,554,432 ns" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_l1pm_ctl2[] = {
	{ 0, 1, "poscale", "T_POWER_ON Scale", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "2 us", "10 us", "100 us" } } },
	{ 3, 7, "portpo", "T_POWER_ON Value", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_l1pm_sts[] = {
	{ 0, 0, "la", "Link Activation", PRDV_HEX },
	{ -1, -1, NULL }
};


static const pcieadm_cfgspace_print_t pcieadm_cap_l1pm_v1[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "caps", "L1 PM Substates Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_l1pm_cap },
	{ 0x8, 4, "ctl1", "L1 PM Substates Control 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_l1pm_ctl1 },
	{ 0xc, 4, "ctl2", "L1 PM Substates Control 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_l1pm_ctl2 },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_l1pm_v2[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "caps", "L1 PM Substates Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_l1pm_cap },
	{ 0x8, 4, "ctl1", "L1 PM Substates Control 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_l1pm_ctl1 },
	{ 0xc, 4, "ctl2", "L1 PM Substates Control 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_l1pm_ctl2 },
	{ 0x10, 4, "sts", "L1 PM Substates Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_l1pm_sts },
	{ -1, -1, NULL }
};

/*
 * Latency Tolerance Reporting (LTR)
 */
static const pcieadm_regdef_t pcieadm_regdef_ltr[] = {
	{ 0, 9, "latval", "Latency Value", PRDV_HEX },
	{ 10, 12, "latscale", "Latency Scale", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1 ns", "32 ns", "1024 ns",
	    "32,768 ns", "1,048,576 ns", "33,554,432 ns" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_ltr[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "snoop", "Max Snoop Latency",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ltr },
	{ 0x6, 2, "nosnoop", "Max No-Snoop Latency",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ltr },
	{ -1, -1, NULL }
};

/*
 * Alternative Routing ID
 */
static const pcieadm_regdef_t pcieadm_regdef_ari_cap[] = {
	{ 0, 0, "mfvcfg", "MFVC Function Groups", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "acsfg", "ACS Function Groups", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 15, "nfunc", "Next Function Number", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ari_ctl[] = {
	{ 0, 0, "mfvcfg", "MFVC Function Groups", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "acsfg", "ACS Function Groups", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 6, "fgrp", "Function Group", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_ari[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "cap", "ARI Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ari_cap },
	{ 0x6, 2, "ctl", "ARI Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ari_ctl },
	{ -1, -1, NULL }
};

/*
 * PASID
 */
static const pcieadm_regdef_t pcieadm_regdef_pasid_cap[] = {
	{ 1, 1, "exec", "Execution Permission", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 2, 2, "priv", "Privileged Mode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 12, "width", "Max PASID Width", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pasid_ctl[] = {
	{ 0, 0, "pasid", "PASID", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "exec", "Execution Permission", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "priv", "Privileged Mode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};


static const pcieadm_cfgspace_print_t pcieadm_cap_pasid[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "cap", "PASID Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pasid_cap },
	{ 0x6, 2, "ctl", "PASID Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pasid_ctl },
	{ -1, -1, NULL }
};

/*
 * "Advanced Features"
 */
static const pcieadm_regdef_t pcieadm_regdef_af_cap[] = {
	{ 0, 0, "tp", "Transactions Pending", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "flr", "Function Level Reset", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_af_ctl[] = {
	{ 0, 0, "flr", "Function Level Reset", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_af_sts[] = {
	{ 0, 0, "tp", "Transactions Pending", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "none pending", "pending" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_af[] = {
	{ 0x2, 2, "cap", "AF Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_af_cap },
	{ 0x4, 1, "ctl", "AF Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_af_ctl },
	{ 0x5, 1, "sts", "AF Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_af_sts },
	{ -1, -1, NULL }
};

/*
 * Multicast
 */
static const pcieadm_regdef_t pcieadm_regdef_mcast_cap[] = {
	{ 0, 5, "maxgrp", "Max Group", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 0, 1 } } },
	{ 8, 13, "winsize", "Window Size (raw)", PRDV_HEX },
	{ 15, 15, "ecrc", "ECRC Regeneration", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_mcast_ctl[] = {
	{ 0, 5, "numgrp", "Number of Groups", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 0, 1 } } },
	{ 15, 15, "enable", "Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_mcast_base[] = {
	{ 0, 5, "index", "Multicast Index Position", PRDV_HEX },
	{ 12, 63, "addr", "Base Address", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 12 } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_mcast_overlay[] = {
	{ 0, 5, "size", "Overlay Size (raw)", PRDV_HEX },
	{ 6, 63, "addr", "Overlay Base Address", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 6 } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_mcast[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "cap", "Multicast Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_mcast_cap },
	{ 0x6, 2, "ctl", "Multicast Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_mcast_ctl },
	{ 0x8, 8, "base", "Multicast Base Address",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_mcast_base },
	{ 0x10, 8, "rx", "Multicast Receive", pcieadm_cfgspace_print_hex },
	{ 0x18, 8, "block", "Multicast Block All", pcieadm_cfgspace_print_hex },
	{ 0x20, 8, "blockun", "Multicast Block Untranslated",
	    pcieadm_cfgspace_print_hex },
	{ 0x28, 8, "overlay", "Multicast Overlay BAR",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_mcast_overlay },
	{ -1, -1, NULL }
};

/*
 * Various vendor extensions
 */
static const pcieadm_regdef_t pcieadm_regdef_vsec[] = {
	{ 0, 15, "id", "ID", PRDV_HEX },
	{ 16, 19, "rev", "Revision", PRDV_HEX },
	{ 20, 31, "len", "Length", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_vs[] = {
	{ 0x2, 2, "length", "Length", pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_vsec[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "header", "Vendor-Specific Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_vsec },
	{ -1, -1, NULL }
};

/*
 * Data Link Feature
 */
static const pcieadm_regdef_t pcieadm_regdef_dlf_cap[] = {
	{ 0, 0, "lsfc", "Local Scaled Flow Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 31, 31, "dlex", "Data Link Exchange", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_dlf_sts[] = {
	{ 0, 0, "rsfc", "Remote Scaled Flow Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 31, 31, "valid", "Remote Data Link Feature Valid", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "invalid", "valid" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_dlf[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "Data Link Feature Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dlf_cap },
	{ 0x8, 4, "sts", "Data Link Feature Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dlf_sts },
	{ -1, -1, NULL }
};

/*
 * 16.0 GT/s cap
 */
static const pcieadm_regdef_t pcieadm_regdef_16g_cap[] = {
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_16g_ctl[] = {
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_16g_sts[] = {
	{ 0, 0, "eqcomp", "Equalization 16.0 GT/s Complete", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 1, 1, "eqp1", "Equalization 16.0 GT/s Phase 1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 2, 2, "eqp2", "Equalization 16.0 GT/s Phase 2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 3, 3, "eqp3", "Equalization 16.0 GT/s Phase 3", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 4, 4, "req", "Link Equalization Request 16.0 GT/s", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_16g_eq[] = {
	{ 0, 3, "dstxpre", "Downstream Port 16.0 GT/s Transmitter Preset",
	    PRDV_HEX },
	{ 4, 7, "ustxpre", "Upstream Port 16.0 GT/s Transmitter Preset",
	    PRDV_HEX },
	{ -1, -1, NULL }
};

static void
pcieadm_cfgspace_print_16geq(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	if (walkp->pcw_nlanes == 0) {
		warnx("failed to capture lane count, but somehow have "
		    "Physical Layer 16.0 GT/s cap");
		return;
	}

	for (uint_t i = 0; i < walkp->pcw_nlanes; i++) {
		char eqshort[32], eqhuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(eqshort, sizeof (eqshort), "lane%u", i);
		(void) snprintf(eqhuman, sizeof (eqhuman), "Lane %u EQ Control",
		    i);
		p.pcp_off = print->pcp_off + i * 1;
		p.pcp_len = 1;
		p.pcp_short = eqshort;
		p.pcp_human = eqhuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_16g_eq;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_16g[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "16.0 GT/s Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_16g_cap },
	{ 0x8, 4, "ctl", "16.0 GT/s Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_16g_ctl },
	{ 0xc, 4, "sts", "16.0 GT/s Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_16g_sts },
	{ 0x10, 4, "ldpmis", "16.0 GT/s Local Data Parity Mismatch",
	    pcieadm_cfgspace_print_hex },
	{ 0x14, 4, "frpmis", "16.0 GT/s First Retimer Data Parity Mismatch",
	    pcieadm_cfgspace_print_hex },
	{ 0x18, 4, "srpmis", "16.0 GT/s Second Retimer Data Parity Mismatch",
	    pcieadm_cfgspace_print_hex },
	{ 0x1c, 4, "rsvd", "16.0 GT/s Second Retimer Data Parity Mismatch",
	    pcieadm_cfgspace_print_hex },
	{ 0x20, 1, "eqctl", "16.0 GT/s EQ Control",
	    pcieadm_cfgspace_print_16geq },
	{ -1, -1, NULL }
};

/*
 * Receiver Margining
 */
static const pcieadm_regdef_t pcieadm_regdef_margin_cap[] = {
	{ 0, 0, "sw", "Margining uses Driver Software", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_margin_sts[] = {
	{ 0, 0, "ready", "Margining Ready", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 1, 1, "sw", "Margining Software Ready", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_margin_lane[] = {
	{ 0, 2, "rxno", "Receiver Number", PRDV_HEX },
	{ 3, 5, "type", "Margin Type", PRDV_HEX },
	{ 6, 6, "model", "Usage Model", PRDV_HEX },
	{ 8, 15, "payload", "Margin Payload", PRDV_HEX },
	{ -1, -1, NULL }
};

static void
pcieadm_cfgspace_print_margin(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	if (walkp->pcw_nlanes == 0) {
		warnx("failed to capture lane count, but somehow have "
		    "lane margining capability");
		return;
	}

	for (uint_t i = 0; i < walkp->pcw_nlanes; i++) {
		char mshort[32], mhuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(mshort, sizeof (mshort), "lane%uctl", i);
		(void) snprintf(mhuman, sizeof (mhuman), "Lane %u Margining "
		    "Control", i);
		p.pcp_off = print->pcp_off + i * 4;
		p.pcp_len = 2;
		p.pcp_short = mshort;
		p.pcp_human = mhuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_margin_lane;

		p.pcp_print(walkp, &p, p.pcp_arg);

		(void) snprintf(mshort, sizeof (mshort), "lane%usts", i);
		(void) snprintf(mhuman, sizeof (mhuman), "Lane %u Margining "
		    "Status", i);
		p.pcp_off = print->pcp_off + 2 + i * 4;
		p.pcp_len = 2;
		p.pcp_short = mshort;
		p.pcp_human = mhuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_margin_lane;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_margin[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "cap", "Margining Port Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_margin_cap },
	{ 0x6, 2, "sts", "Margining Port Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_margin_sts },
	{ 0x8, 4, "lane", "Margining Lane", pcieadm_cfgspace_print_margin },
	{ -1, -1, NULL }
};

/*
 * Serial Number Capability
 */
static void
pcieadm_cfgspace_print_sn(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	char sn[64];
	uint16_t off = walkp->pcw_capoff + print->pcp_off;

	(void) snprintf(sn, sizeof (sn),
	    "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
	    walkp->pcw_data->pcb_u8[off + 7], walkp->pcw_data->pcb_u8[off + 6],
	    walkp->pcw_data->pcb_u8[off + 5], walkp->pcw_data->pcb_u8[off + 4],
	    walkp->pcw_data->pcb_u8[off + 3], walkp->pcw_data->pcb_u8[off + 2],
	    walkp->pcw_data->pcb_u8[off + 1], walkp->pcw_data->pcb_u8[off]);

	pcieadm_cfgspace_puts(walkp, print, sn);
}

static const pcieadm_cfgspace_print_t pcieadm_cap_sn[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 8, "sn", "Serial Number", pcieadm_cfgspace_print_sn },
	{ -1, -1, NULL }
};

/*
 * TLP Processing Hints (TPH)
 */
static const pcieadm_regdef_t pcieadm_regdef_tph_cap[] = {
	{ 0, 0, "nost", "No ST Mode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "ivec", "Interrupt Vector Mode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 2, 2, "dev", "Device Specific Mode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "exttph", "Extended TPH Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 9, 10, "loc", "ST Table Location", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Not Present",
	    "In Capability Structure", "MSI-X" } } },
	{ 16, 26, "size", "ST Table Size", PRDV_HEX, { .prdv_hex = { 0, 1 } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_tph_ctl[] = {
	{ 0, 2, "mode", "ST Mode Select", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "No ST", "Interrupt Vector",
	    "Device Specific" } } },
	{ 8, 9, "en", "TPH Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Not Permitted", "TPH", NULL,
	    "TPH and Extended TPH" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_tph_st[] = {
	{ 0, 7, "low", "ST Lower", PRDV_HEX },
	{ 8, 15, "up", "ST Upper", PRDV_HEX },
	{ -1, -1, NULL }
};

/*
 * The TPH ST table is only conditionally present in the capability. So we need
 * to read the TPH capability register and then check if the table location and
 * size are set here.
 */
static void
pcieadm_cfgspace_print_tphst(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint_t nents;
	uint32_t tphcap = walkp->pcw_data->pcb_u32[(walkp->pcw_capoff + 4) / 4];

	if (bitx32(tphcap, 10, 9) != 1) {
		return;
	}

	nents = bitx32(tphcap, 26, 16) + 1;
	for (uint_t i = 0; i < nents; i++) {
		char tshort[32], thuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(tshort, sizeof (tshort), "st%u", i);
		(void) snprintf(thuman, sizeof (thuman), "ST Table %u",
		    i);
		p.pcp_off = print->pcp_off + i * 2;
		p.pcp_len = 2;
		p.pcp_short = tshort;
		p.pcp_human = thuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_tph_st;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_tph[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "TPH Requester Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_tph_cap },
	{ 0x8, 4, "ctl", "TPH Requester Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_tph_ctl },
	{ 0xc, 2, "table", "ST Table", pcieadm_cfgspace_print_tphst },
	{ -1, -1, NULL }
};

/*
 * SR-IOV
 */
static const pcieadm_regdef_t pcieadm_regdef_sriov_cap[] = {
	{ 0, 0, "migration", "Migration", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "ari", "ARI Capable Hierarchy Preserved", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unpreserved", "preserved" } } },
	{ 2, 2, "vf10b", "VF 10-bit Tag Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unpreserved", "preserved" } } },
	{ 21, 31, "inum", "VF Migration Interrupt Message Number", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_sriov_ctl[] = {
	{ 0, 0, "vf", "VF", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "vfm", "VF Migration", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "vfmi", "VF Migration Interrupt", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "ari", "ARI Capable Hierarchy", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "vf10b", "VF 10-bit Tag Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_sriov_sts[] = {
	{ 0, 0, "vfm", "VF Migration", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "none", "requested" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_sriov_pgsup[] = {
	{ 0, 31, "pgsz", "Supported Page Sizes", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "4 KB", "8 KB", "16 KB", "32 KB",
	    "64 KB", "128 KB", "256 KB", "512 KB", "1 MB", "2 MB", "4 MB",
	    "8 MB", "16 MB", "32 MB", "64 MB", "128 MB", "256 MB", "512 MB",
	    "1 GB", "2 GB", "4 GB", "8 GB", "16 GB", "32 GB", "64 GB",
	    "128 GB", "256 GB", "512 GB", "1 TB", "2 TB", "4 TB", "8 TB" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_sriov_pgen[] = {
	{ 0, 31, "pgsz", "System Page Sizes", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "4 KB", "8 KB", "16 KB", "32 KB",
	    "64 KB", "128 KB", "256 KB", "512 KB", "1 MB", "2 MB", "4 MB",
	    "8 MB", "16 MB", "32 MB", "64 MB", "128 MB", "256 MB", "512 MB",
	    "1 GB", "2 GB", "4 GB", "8 GB", "16 GB", "32 GB", "64 GB",
	    "128 GB", "256 GB", "512 GB", "1 TB", "2 TB", "4 TB", "8 TB" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_sriov_mig[] = {
	{ 0, 2, "bir", "VF Migration State BIR", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "BAR 0", "BAR 1", "BAR 2", "BAR 3",
	    "BAR 4", "BAR 5" } } },
	{ 3, 31, "offset", "VF Migration State Offset", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 3 } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_sriov[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "SR-IOV Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sriov_cap },
	{ 0x8, 2, "ctl", "SR-IOV Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sriov_ctl },
	{ 0xa, 2, "sts", "SR-IOV Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sriov_sts },
	{ 0xc, 2, "initvfs", "Initial VFs", pcieadm_cfgspace_print_hex },
	{ 0xe, 2, "totvfs", "Total VFs", pcieadm_cfgspace_print_hex },
	{ 0x10, 2, "numvfs", "Number VFs", pcieadm_cfgspace_print_hex },
	{ 0x12, 1, "dep", "Function Dependency Link",
	    pcieadm_cfgspace_print_hex },
	{ 0x14, 2, "offset", "First VF Offset", pcieadm_cfgspace_print_hex },
	{ 0x16, 2, "stride", "VF Stride", pcieadm_cfgspace_print_hex },
	{ 0x1a, 2, "devid", "VF Device ID", pcieadm_cfgspace_print_hex },
	{ 0x1c, 4, "pgsz", "Supported Page Sizes",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sriov_pgsup },
	{ 0x20, 4, "pgsz", "System Page Sizes",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sriov_pgen },
	{ 0x24, 24, "vfbar", "Virtual Base Address Register",
	    pcieadm_cfgspace_print_bars },
	{ 0x3c, 4, "migration", "VF Migration State Array",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_sriov_mig },
	{ -1, -1, NULL }
};

/*
 * PCI-X
 */
static const pcieadm_regdef_t pcieadm_regdef_pcix_dev_ctl[] = {
	{ 0, 0, "dper", "Data Parity Error Recovery", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "ro", "Relaxed Ordering", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 3, "maxread", "Maximum Memory Read Byte Count", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "512 bytes", "1024 bytes",
	    "2048 bytes", "4096 bytes" } } },
	{ 4, 6, "maxsplit", "Maximum Outstanding Split Transactions",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "1", "2", "3", "4", "8",
	    "12", "16", "32" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcix_dev_sts[] = {
	{ 0, 2, "func", "Function Number", PRDV_HEX },
	{ 3, 7, "dev", "Device Number", PRDV_HEX },
	{ 8, 15, "bus", "Bus Number", PRDV_HEX },
	{ 16, 16, "64bit", "64-bit Device", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported (32-bit)",
	    "supported" } } },
	{ 17, 17, "133mhz", "133 MHz Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported (66 MHz)",
	    "supported" } } },
	{ 18, 18, "spcodis", "Split Completion Discarded", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 19, 19, "unspco", "Unexpected Split Completion", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 20, 20, "complex", "Device Complexity", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "simple", "bridge" } } },
	{ 21, 22, "maxread", "Designed Maximum Memory Read Byte Count",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "512 bytes",
	    "1024 bytes", "2048 bytes", "4096 bytes" } } },
	{ 23, 25, "maxsplit", "Designed Maximum Outstanding Split Transactions",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "1", "2", "3", "4", "8",
	    "12", "16", "32" } } },
	{ 26, 28, "maxcread", "Designed Maximum Cumulative Read Size",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "8/1KB", "16/2KB",
	    "32/4KB", "64/8KB", "128/16KB", "256/32KB", "512/64KB",
	    "1024/128KB" } } },
	{ 29, 29, "rxspcoer", "Received Split Completion Error Message",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcix_sec_sts[] = {
	{ 0, 0, "64bit", "64-bit Device", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported (32-bit)",
	    "supported" } } },
	{ 1, 1, "133mhz", "133 MHz Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported (66 MHz)",
	    "supported" } } },
	{ 2, 2, "spcodis", "Split Completion Discarded", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 3, 3, "unspco", "Unexpected Split Completion", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 4, 4, "spcoor", "Split Completion Overrun", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 5, 5, "sprde", "Split Request Delayed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 6, 8, "freq", "Secondary Clock Frequency", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "conventional", "66 MHz", "100 Mhz",
	    "133 MHz" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcix_bridge_sts[] = {
	{ 0, 2, "func", "Function Number", PRDV_HEX },
	{ 3, 7, "dev", "Device Number", PRDV_HEX },
	{ 8, 15, "bus", "Bus Number", PRDV_HEX },
	{ 16, 16, "64bit", "64-bit Device", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported (32-bit)",
	    "supported" } } },
	{ 17, 17, "133mhz", "133 MHz Capable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported (66 MHz)",
	    "supported" } } },
	{ 18, 18, "spcodis", "Split Completion Discarded", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 19, 19, "unspco", "Unexpected Split Completion", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 20, 20, "spcoor", "Split Completion Overrun", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 21, 21, "sprde", "Split Request Delayed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pcix_bridge_split[] = {
	{ 0, 15, "cap", "Split Transaction Capacity", PRDV_HEX },
	{ 16, 31, "limit", "Split Transaction Commitment Limit", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_pcix_dev[] = {
	{ 0x2, 2, "ctl", "PCI-X Command",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcix_dev_ctl },
	{ 0x4, 4, "sts", "PCI-X Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcix_dev_sts },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_pcix_bridge[] = {
	{ 0x2, 2, "secsts", "PCI-X Secondary Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcix_sec_sts },
	{ 0x4, 4, "sts", "PCI-X Bridge Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcix_bridge_sts },
	{ 0x8, 4, "ussplit", "Upstream Split Transaction",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcix_bridge_split },
	{ 0x8, 4, "dssplit", "Downstream Split Transaction",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcix_bridge_split },
	{ -1, -1, NULL }
};

/*
 * Dynamic Power Allocation
 */
static const pcieadm_regdef_t pcieadm_regdef_dpa_cap[] = {
	{ 0, 4, "substates", "Substate Max", PRDV_HEX,
	    { .prdv_hex = { 0, 1 } } },
	{ 8, 9, "tlu", "Transition Latency Unit", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1 ms", "10 ms", "100 ms" } } },
	{ 12, 13, "pas", "Power Allocation Scale", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "10.0x", "1.0x", "0.1x",
	    "0.01x" } } },
	{ 16, 23, "tlv0", "Transition Latency Value 0", PRDV_HEX },
	{ 24, 31, "tlv0", "Transition Latency Value 1", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_dpa_sts[] = {
	{ 0, 4, "substate", "Substate Status", PRDV_HEX },
	{ 8, 8, "ctlen", "Substate Control Enabled", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_dpa_ctl[] = {
	{ 0, 4, "substate", "Substate Control", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_dpa[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "DPA Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dpa_cap },
	{ 0x8, 4, "lat", "DPA Latency Indicator", pcieadm_cfgspace_print_hex },
	{ 0xc, 2, "sts", "DPA Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dpa_sts },
	{ 0xe, 2, "sts", "DPA Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dpa_ctl },
	{ 0x10, 1, "paa", "DPA Power Allocation Array",
	    pcieadm_cfgspace_print_dpa_paa },
	{ -1, -1, NULL }
};

/*
 * Power Budgeting
 */
static const pcieadm_regdef_t pcieadm_regdef_powbudg_data[] = {
	{ 0, 7, "base", "Base Power", PRDV_HEX },
	{ 8, 9, "scale", "Data Scale", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1.0x", "0.1x", "0.01x",
	    "0.001x" } } },
	{ 10, 12, "pmsub", "PM Substate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Default", "Device Specific",
	    "Device Specific", "Device Specific", "Device Specific",
	    "Device Specific", "Device Specific", "Device Specific" } } },
	{ 13, 14, "pmstate", "PM State", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "D0", "D1", "D2", "D3" } } },
	{ 15, 17, "type", "Type", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "PME Aux", "Axiliary", "Idle",
	    "Sustained", "Sustained - EPRS", "Maximum - EPRS", NULL,
	    "Maximum" } } },
	{ 18, 20, "rail", "Power Rail", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Power (12V)", "Power (3.3V)",
	    "Power (1.5V or 1.8V)", NULL, NULL, NULL, NULL, "Thermal" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_powbudg_cap[] = {
	{ 0, 0, "sa", "System Allocated", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};


static const pcieadm_cfgspace_print_t pcieadm_cap_powbudg[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 1, "sel", "Data Select", pcieadm_cfgspace_print_hex },
	{ 0x8, 4, "data", "Data Regiser", pcieadm_cfgspace_print_regdef,
	    pcieadm_regdef_powbudg_data },
	{ 0xc, 0x1, "cap", "Power Budget Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_powbudg_cap },
	{ -1, -1, NULL }
};

/*
 * Precision Time Management
 */
static const pcieadm_regdef_t pcieadm_regdef_ptm_cap[] = {
	{ 0, 0, "req", "PTM Requester", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "resp", "PTM Responder", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 2, 2, "root", "PTM Root", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 3, 3, "eptm", "ePTM", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 15, "gran", "Local Clock Granularity", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ptm_ctl[] = {
	{ 0, 0, "en", "PTM Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "root", "Root Select", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 15, "gran", "Effective Granularity", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_info_ptm[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "PTM Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ptm_cap },
	{ 0x8, 4, "cap", "PTM Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ptm_ctl },
	{ -1, -1, NULL }
};

/*
 * Address Translation Services (ATS)
 */
static const pcieadm_regdef_t pcieadm_regdef_ats_cap[] = {
	{ 0, 4, "invqd", "Invalidate Queue Depth", PRDV_HEX },
	{ 5, 5, "pgalign", "Page Aligned Request", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not required", "required" } } },
	{ 6, 6, "glbinv", "Global Invalidate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 7, 7, "relo", "Relaxed Ordering", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ats_ctl[] = {
	{ 0, 4, "stu", "Smallest Translation Unit", PRDV_HEX },
	{ 15, 15, "en", "Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_ats[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "cap", "ATS Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ats_cap },
	{ 0x6, 2, "cap", "ATS Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ats_ctl },
	{ -1, -1, NULL }
};

/*
 * Page Request
 */
static const pcieadm_regdef_t pcieadm_regdef_pgreq_ctl[] = {
	{ 0, 0, "en", "Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "reset", "Reset", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_pgreq_sts[] = {
	{ 0, 0, "rf", "Response Failure", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 1, 1, "uprgi", "Unexpected Page Request Group Index", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 8, 8, "stopped", "Stopped", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 15, 15, "prgrpreq", "PRG Response PASID", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not required", "required" } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_pgreq[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "ctl", "Page Request Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pgreq_ctl },
	{ 0x6, 2, "ctl", "Page Request Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pgreq_sts },
	{ 0x8, 4, "cap", "Outstanding Page Request Capacity",
	    pcieadm_cfgspace_print_hex },
	{ 0xc, 4, "alloc", "Outstanding Page Request Allocation",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

/*
 * NULL Capability
 */
static const pcieadm_cfgspace_print_t pcieadm_cap_null[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ -1, -1, NULL }
};

/*
 * Downstream Port Containment
 */
static const pcieadm_regdef_t pcieadm_regdef_dpc_cap[] = {
	{ 0, 4, "inum", "DPC Interrupt Message Number", PRDV_HEX },
	{ 5, 5, "rpext", "Root Port Extensions", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 6, 6, "ptlpeb", "Poisoned TLP Egress Blocking", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 7, 7, "swtrig", "Software Triggering", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 11, "logsz", "RP PIO Log Size", PRDV_HEX },
	{ 12, 12, "errcorr", "DL_Active ERR_COR Signaling", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_dpc_ctl[] = {
	{ 0, 1, "trigger", "DPC Trigger", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled, fatal",
	    "enabled, non-fatal" } } },
	{ 2, 2, "comp", "Completion Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Completer Abort",
	    "Unsupported Request" } } },
	{ 3, 3, "intr", "Interrupt",
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "errcor", "ERR_COR",
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 5, "ptlpeb", "Poisoned TLP Egress Blocking", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 6, "swtrig", "Software Trigger", PRDV_HEX },
	{ 7, 7, "corerr", "DL_Active ERR_COR",
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 8, "sigsfw", "SIG_SFW",
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_dpc_sts[] = {
	{ 0, 0, "trigger", "Trigger Status", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not triggered", "triggered" } } },
	{ 1, 2, "reason", "Trigger Reason", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unmasked uncorrectable",
	    "ERR_NONFATAL received", "ERR_FATAL received",
	    "see extension" } } },
	{ 3, 3, "istatus", "Interrupt Status", PRDV_HEX },
	{ 4, 4, "rpbusy", "RP Busy", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 5, 6, "extreason", "Trigger Reason Extension", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "RP PIO", "Software Trigger" } } },
	{ 8, 12, "feptr", "RP PIO, First Error Pointer", PRDV_HEX },
	{ 13, 13, "sigsfw", "SIG_SFW Status", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_dpc_rppio_bits[] = {
	{ 0, 0, "cfgur", "Configuration Request UR Completion", PRDV_HEX },
	{ 1, 1, "cfgca", "Configuration Request CA Completion", PRDV_HEX },
	{ 2, 2, "cfgcto", "Configuration Request Completion Timeout",
	    PRDV_HEX },
	{ 8, 8, "iour", "I/O UR Completion", PRDV_HEX },
	{ 9, 9, "ioca", "I/O CA Completion", PRDV_HEX },
	{ 10, 10, "iocto", "I/O Completion Timeout", PRDV_HEX },
	{ 8, 8, "memur", "Memory UR Completion", PRDV_HEX },
	{ 9, 9, "memca", "Memory CA Completion", PRDV_HEX },
	{ 10, 10, "memcto", "Memory Completion Timeout", PRDV_HEX },
	{ -1, -1, NULL }
};

static void
pcieadm_cfgspace_print_dpc_rppio(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint32_t cap = walkp->pcw_data->pcb_u32[(walkp->pcw_capoff + 4) / 4];

	if (bitx32(cap, 5, 5) == 0) {
		return;
	}

	pcieadm_cfgspace_print_regdef(walkp, print, arg);
}

static void
pcieadm_cfgspace_print_dpc_piohead(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint32_t cap = walkp->pcw_data->pcb_u32[(walkp->pcw_capoff + 4) / 4];
	uint32_t nwords = bitx32(cap, 11, 8);

	if (bitx32(cap, 5, 5) == 0 || nwords < 4) {
		return;
	}

	pcieadm_cfgspace_print_hex(walkp, print, NULL);
}

static void
pcieadm_cfgspace_print_dpc_impspec(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint32_t cap = walkp->pcw_data->pcb_u32[(walkp->pcw_capoff + 4) / 4];
	uint32_t nwords = bitx32(cap, 11, 8);

	if (bitx32(cap, 5, 5) == 0 || nwords < 5) {
		return;
	}

	pcieadm_cfgspace_print_hex(walkp, print, NULL);
}

static void
pcieadm_cfgspace_print_dpc_tlplog(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint32_t cap = walkp->pcw_data->pcb_u32[(walkp->pcw_capoff + 4) / 4];
	int32_t nwords = (int32_t)bitx32(cap, 11, 8);

	if (nwords == 0 || bitx32(cap, 5, 5) == 0) {
		return;
	}

	if (nwords <= 9) {
		nwords -= 5;
	} else {
		nwords -= 4;
	}

	for (int32_t i = 0; i < nwords; i++) {
		char tlpshort[32], tlphuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(tlpshort, sizeof (tlpshort), "%s%u",
		    print->pcp_short, i);
		(void) snprintf(tlphuman, sizeof (tlphuman), "%s %u",
		    print->pcp_human, i);
		p.pcp_off = print->pcp_off + i * 4;
		p.pcp_len = 4;
		p.pcp_short = tlpshort;
		p.pcp_human = tlphuman;
		p.pcp_print = pcieadm_cfgspace_print_hex;
		p.pcp_arg = NULL;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_dpc[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 2, "cap", "DPC Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dpc_cap },
	{ 0x6, 2, "ctl", "DPC Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dpc_ctl },
	{ 0x8, 2, "sts", "DPC Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_dpc_sts },
	{ 0xa, 2, "srcid", "DPC Error Source ID",
	    pcieadm_cfgspace_print_hex },
	{ 0x10, 4, "rppiosts", "RP PIO Status",
	    pcieadm_cfgspace_print_dpc_rppio, pcieadm_regdef_dpc_rppio_bits },
	{ 0x14, 4, "rppiomask", "RP PIO Mask ID",
	    pcieadm_cfgspace_print_dpc_rppio, pcieadm_regdef_dpc_rppio_bits },
	{ 0x14, 4, "rppiosev", "RP PIO Severity",
	    pcieadm_cfgspace_print_dpc_rppio, pcieadm_regdef_dpc_rppio_bits },
	{ 0x18, 4, "rppiose", "RP PIO SysError",
	    pcieadm_cfgspace_print_dpc_rppio, pcieadm_regdef_dpc_rppio_bits },
	{ 0x1c, 4, "rppioex", "RP PIO Exception",
	    pcieadm_cfgspace_print_dpc_rppio, pcieadm_regdef_dpc_rppio_bits },
	{ 0x20, 4, "rppiohl0", "RP PIO Header Log 0",
	    pcieadm_cfgspace_print_dpc_piohead },
	{ 0x24, 4, "rppiohl1", "RP PIO Header Log 1",
	    pcieadm_cfgspace_print_dpc_piohead },
	{ 0x28, 4, "rppiohl2", "RP PIO Header Log 2",
	    pcieadm_cfgspace_print_dpc_piohead },
	{ 0x2c, 4, "rppiohl3", "RP PIO Header Log 3",
	    pcieadm_cfgspace_print_dpc_piohead },
	{ 0x30, 4, "impspec", "RP PIO ImpSpec Log",
	    pcieadm_cfgspace_print_dpc_impspec },
	{ 0x34, 16, "tlplog", "RP PIO TLP Prefix Log",
	    pcieadm_cfgspace_print_dpc_tlplog },
	{ -1, -1, NULL }
};

/*
 * Virtual Channel Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_vc_cap1[] = {
	{ 0, 2, "count", "Extended VC Count", PRDV_HEX },
	{ 4, 6, "lpcount", "Low Priority Extended VC Count", PRDV_HEX },
	{ 8, 9, "refclk", "Reference Clock", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "100ns" } } },
	{ 10, 11, "patsz", "Port Arbitration Table Size", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "1 bit", "2 bits", "4 bits",
	    "8 bits" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_vc_cap2[] = {
	{ 0, 7, "arbcap", "VC Arbitration Capability", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "hardware fixed",
	    "32 phase weighted round robin", "64 phase weighted round robin",
	    "128 phase weighted round robin" } } },
	{ 24, 31, "offset", "VC Arbitration Table Offset", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_vc_ctl[] = {
	{ 0, 0, "loadtbl", "Load VC Arbitration Table", PRDV_HEX },
	{ 1, 3, "arbtype", "VC Arbitration Select", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "hardware fixed",
	    "32 phase weighted round robin", "64 phase weighted round robin",
	    "128 phase weighted round robin" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_vc_sts[] = {
	{ 0, 0, "table", "VC Arbitration Table Status", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_vc_rsrccap[] = {
	{ 0, 7, "arbcap", "Port Arbitration Capability", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "hardware fixed",
	    "32 phase weighted round robin", "64 phase weighted round robin",
	    "128 phase weighted round robin",
	    "128 phase time-based weighted round robin",
	    "256 phase weighted round robin" } } },
	{ 14, 14, "aps", "Advanced Packet Switching", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 15, 15, "rstx", "Reject Snoop Transactions", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 16, 22, "nslots", "Maximum Time Slots", PRDV_HEX,
	    { .prdv_hex = { 0, 1 } } },
	{ 24, 31, "offset", "VC Arbitration Table Offset", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_vc_rsrcctl[] = {
	{ 0, 7, "tcmap", "TC/VC Map", PRDV_HEX },
	{ 16, 16, "loadtbl", "Load VC Arbitration Table", PRDV_HEX },
	{ 17, 19, "arbtype", "Port Arbitration Select", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "hardware fixed",
	    "32 phase weighted round robin", "64 phase weighted round robin",
	    "128 phase weighted round robin",
	    "128 phase time-based weighted round robin",
	    "256 phase weighted round robin" } } },
	{ 24, 26, "vcid", "VC ID", PRDV_HEX },
	{ 31, 31, "en", "VC Enable",
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_vc_rsrcsts[] = {
	{ 0, 0, "table", "Port Arbitration Table Status", PRDV_HEX },
	{ -1, -1, NULL }
};

static void
pcieadm_cfgspace_print_vc_rsrc(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint32_t cap = walkp->pcw_data->pcb_u32[(walkp->pcw_capoff + 4) / 4];
	uint32_t nents = bitx32(cap, 2, 0) + 1;

	for (uint32_t i = 0; i < nents; i++) {
		char vcshort[32], vchuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(vcshort, sizeof (vcshort), "rsrccap%u", i);
		(void) snprintf(vchuman, sizeof (vchuman), "VC Resource %u "
		    "Capability", i);
		p.pcp_off = print->pcp_off + i * 0x10;
		p.pcp_len = 4;
		p.pcp_short = vcshort;
		p.pcp_human = vchuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_vc_rsrccap;

		p.pcp_print(walkp, &p, p.pcp_arg);

		(void) snprintf(vcshort, sizeof (vcshort), "rsrcctl%u", i);
		(void) snprintf(vchuman, sizeof (vchuman), "VC Resource %u "
		    "Control", i);
		p.pcp_off = print->pcp_off + i * 0x10 + 4;
		p.pcp_len = 4;
		p.pcp_short = vcshort;
		p.pcp_human = vchuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_vc_rsrcctl;

		p.pcp_print(walkp, &p, p.pcp_arg);

		(void) snprintf(vcshort, sizeof (vcshort), "rsrcsts%u", i);
		(void) snprintf(vchuman, sizeof (vchuman), "VC Resource %u "
		    "Status", i);
		p.pcp_off = print->pcp_off + i * 0x10 + 0xa;
		p.pcp_len = 2;
		p.pcp_short = vcshort;
		p.pcp_human = vchuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_vc_rsrcsts;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_vc[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap1", "Port VC Capability 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_vc_cap1 },
	{ 0x8, 4, "cap2", "Port VC Capability 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_vc_cap2 },
	{ 0xc, 2, "ctl", "Port VC Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_vc_ctl },
	{ 0xe, 2, "sts", "Port VC Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_vc_sts },
	{ 0x10, 12, "vcrec", "VC Resource", pcieadm_cfgspace_print_vc_rsrc },
	{ -1, -1, NULL }
};

/*
 * HyperTransport
 */
static const pcieadm_cfgspace_print_t pcieadm_cap_ht_intr[] = {
	{ 0x2, 1, "index", "Interrupt Discovery Index",
	    pcieadm_cfgspace_print_hex },
	{ 0x4, 4, "dataport", "Interrupt Dataport",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_command_pri[] = {
	{ 0, 4, "unitid", "Base Unit ID", PRDV_HEX },
	{ 5, 9, "count", "Unit Count", PRDV_HEX },
	{ 10, 10, "host", "Master Host", PRDV_HEX },
	{ 11, 11, "dir", "Default Direction", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "towards host",
	    "away from host" } } },
	{ 12, 12, "drop", "Drop on Uninitialized Link", PRDV_HEX },
	{ 13, 15, "cap", "Capability ID", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_command_sec[] = {
	{ 0, 0, "reset", "Warm Reset", PRDV_HEX },
	{ 1, 1, "de", "Double Ended", PRDV_HEX },
	{ 2, 6, "devno", "Device Number", PRDV_HEX },
	{ 7, 7, "chain", "Chain Side", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "from host", "from chain" } } },
	{ 8, 8, "hide", "Host Hide", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "visible", "hidden" } } },
	{ 10, 10, "target", "Act as Target", PRDV_HEX },
	{ 11, 11, "eocerr", "Host Inbound End of Chain Error", PRDV_HEX },
	{ 12, 12, "drop", "Drop on Uninitialized Link", PRDV_HEX },
	{ 13, 15, "cap", "Capability ID", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_linkctl[] = {
	{ 0, 0, "srcid", "Source ID", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "cfl", "CRC Flood", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "cst", "CRC Start Test", PRDV_HEX },
	{ 3, 3, "cfer", "CRC Force Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "linkfail", "Link Failure", PRDV_HEX },
	{ 5, 5, "initcmp", "Initialization Complete", PRDV_HEX },
	{ 6, 6, "eoc", "End of Chain", PRDV_HEX },
	{ 7, 7, "txoff", "Transmitter Off", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "transmitter on",
	    "transmitter off" } } },
	{ 8, 11, "crcerr", "CRC Error", PRDV_HEX },
	{ 12, 12, "isoc", "Isochronous Flow Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 13, 13, "ls", "LDTSTOP# Tristate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 14, 14, "extctl", "Extended CTL Time", PRDV_HEX },
	{ 15, 15, "64b", "64-bit Addressing", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_linkcfg[] = {
	{ 0, 2, "maxin", "Maximum Link Width In", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "8 bits", "16 bits", NULL, "32 bits",
	    "2 bits", "4 bits", NULL, "not connected" } } },
	{ 3, 3, "dwfcinsup", "Doubleword Flow Control In", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 4, 6, "maxout", "Maximum Link Width Out", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "8 bits", "16 bits", NULL, "32 bits",
	    "2 bits", "4 bits", NULL, "not connected" } } },
	{ 7, 7, "dwfcoutsup", "Doubleword Flow Control Out", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 10, "linkin", "Link Width In", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "8 bits", "16 bits", NULL, "32 bits",
	    "2 bits", "4 bits", NULL, "not connected" } } },
	{ 11, 11, "dwfcin", "Doubleword Flow Control In", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 12, 14, "linkout", "Link Width Out", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "8 bits", "16 bits", NULL, "32 bits",
	    "2 bits", "4 bits", NULL, "not connected" } } },
	{ 15, 15, "dwfcout", "Doubleword Flow Control Out", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_rev[] = {
	{ 0, 4, "minor", "Minor Revision", PRDV_HEX },
	{ 5, 7, "major", "Major Revision", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_linkfreq[] = {
	{ 0, 4, "freq", "Link Frequency", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "200 MHz", "300 MHz", "400 MHz",
	    "500 MHz", "600 MHz", "800 MHz", "1000 MHz", "1200 MHz", "1400 MHz",
	    "1600 MHz", "1800 MHz", "2000 MHz", "2200 MHz", "2400 MHz",
	    "2600 MHz", "Vendor Specfic" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_linkerr[] = {
	{ 4, 4, "prot", "Protocol Error", PRDV_HEX },
	{ 5, 5, "over", "Overflow Error", PRDV_HEX },
	{ 6, 6, "eoc", "End of Chain Error", PRDV_HEX },
	{ 7, 7, "ctl", "CTL Timeout", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_linkcap[] = {
	{ 0, 15, "freq", "Link Frequency", PRDV_BITFIELD,
	    .prd_val = { .prdv_strval = { "200 MHz", "300 MHz", "400 MHz",
	    "500 MHz", "600 MHz", "800 MHz", "1000 MHz", "1200 MHz", "1400 MHz",
	    "1600 MHz", "1800 MHz", "2000 MHz", "2200 MHz", "2400 MHz",
	    "2600 MHz", "Vendor Specfic" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_feature[] = {
	{ 0, 0, "isofc", "Isochronous Flow Control", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "ls", "LDTSTOP#", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 2, 2, "crct", "CRC Test Mode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 3, 3, "ectl", "Extended CTL Time", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not required", "required" } } },
	{ 4, 4, "64b", "64-bit Addressing", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 5, 5, "unitid", "UnitID Reorder", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "enabled", "disabled" } } },
	{ 6, 6, "srcid", "Source Identification Extension", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "not required", "required" } } },
	{ 8, 8, "extreg", "Extended Register Set", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 9, 9, "uscfg", "Upstream Configuration", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_error[] = {
	{ 0, 0, "protfl", "Protocol Error Flood", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "ovfl", "Overflow Error Flood", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "protf", "Protocol Error Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "ovf", "Overflow Error Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "eocf", "End of Chain Fatal Error", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 5, "respf", "Response Error Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 6, "crcf", "CRC Error Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 7, 7, "sysf", "System Error Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 8, "chain", "Chain Fail", PRDV_HEX },
	{ 9, 9, "resp", "Response Error", PRDV_HEX },
	{ 10, 10, "protnf", "Protocol Error Non-Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 11, 11, "ovfnf", "Overflow Error Non-Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 12, 12, "eocnf", "End of Chain Error Non-Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 13, 13, "respnf", "Response Error Non-Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 14, 14, "crcnf", "CRC Error Non-Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 15, 15, "sysnf", "System Error Non-Fatal", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_memory[] = {
	{ 0, 8, "base", "Memory Base Upper 8 Bits", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 32 } } },
	{ 9, 15, "limit", "Memory Limit Upper 8 Bits", PRDV_HEX,
	    .prd_val = { .prdv_hex = { 32 } } },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_ht_pri[] = {
	{ 0x2, 2, "command", "Command",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_command_pri },
	{ 0x4, 2, "linkctl0", "Link Control 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkctl },
	{ 0x6, 2, "linkcfg0", "Link Configuration 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkcfg },
	{ 0x8, 2, "linkctl1", "Link Control 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkctl },
	{ 0xa, 2, "linkcfg1", "Link Configuration 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkcfg },
	{ 0xc, 1, "rev", "Revision",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_rev },
	{ 0xd, 1, "linkfreq0", "Link Frequency 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkfreq },
	{ 0xd, 1, "linkerr0", "Link Error 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkerr },
	{ 0xe, 2, "linkfcap0", "Link Frequency Cap 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkcap },
	{ 0x10, 1, "feature", "Feature Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_feature },
	{ 0x11, 1, "linkfreq1", "Link Frequency 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkfreq },
	{ 0x11, 1, "linkerr1", "Link Error 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkerr },
	{ 0x12, 2, "linkfcap1", "Link Frequency Cap 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkcap },
	{ 0x14, 2, "scratch", "Enumeration Scratchpad",
	    pcieadm_cfgspace_print_hex },
	{ 0x16, 2, "error", "Error Handling",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_error },
	{ 0x18, 2, "memory", "Memory",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_memory },
	{ 0x1a, 1, "bus", "Bus Number", pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_ht_sec[] = {
	{ 0x2, 2, "command", "Command",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_command_sec },
	{ 0x4, 2, "linkctl", "Link Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkctl },
	{ 0x6, 2, "linkcfg", "Link Configuration",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkcfg },
	{ 0x8, 1, "rev", "Revision",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_rev },
	{ 0x9, 1, "linkfreq", "Link Frequency 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkfreq },
	{ 0x9, 1, "linkerr", "Link Error 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkerr },
	{ 0xa, 2, "linkfcap", "Link Frequency Cap 0",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_linkcap },
	{ 0xc, 2, "feature", "Feature Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_feature },
	{ 0x10, 2, "scratch", "Enumeration Scratchpad",
	    pcieadm_cfgspace_print_hex },
	{ 0x12, 2, "error", "Error Handling",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_error },
	{ 0x14, 2, "memory", "Memory",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_memory },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ht_msi[] = {
	{ 0, 0, "en", "Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "fixed", "Fixed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ -1, -1, NULL }
};

static void
pcieadm_cfgspace_print_ht_msi_addr(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint8_t fixed = walkp->pcw_data->pcb_u8[walkp->pcw_capoff + 2];

	if (bitx8(fixed, 1, 1) != 0)
		return;

	pcieadm_cfgspace_print_hex(walkp, print, arg);
}

static const pcieadm_cfgspace_print_t pcieadm_cap_ht_msi[] = {
	{ 0x2, 2, "command", "Command",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ht_msi },
	{ 0x4, 8, "address", "MSI Address",
	    pcieadm_cfgspace_print_ht_msi_addr },
	{ -1, -1, NULL }
};

/*
 * Capability related tables
 */
typedef struct pcieadm_cap_vers {
	uint32_t ppr_vers;
	uint32_t ppr_len;
	const pcieadm_cfgspace_print_t *ppr_print;
} pcieadm_cap_vers_t;

typedef struct pcieadm_subcap {
	const char *psub_short;
	const char *psub_human;
} pcieadm_subcap_t;

typedef struct pcieadm_pci_cap pcieadm_pci_cap_t;

typedef void (*pcieadm_cap_info_f)(pcieadm_cfgspace_walk_t *,
    const pcieadm_pci_cap_t *, uint32_t, const pcieadm_cap_vers_t **,
    uint32_t *, const pcieadm_subcap_t **);

struct pcieadm_pci_cap {
	uint32_t ppc_id;
	const char *ppc_short;
	const char *ppc_human;
	pcieadm_cap_info_f ppc_info;
	const pcieadm_cap_vers_t ppc_vers[4];
};

/*
 * Capability version determinations.
 */

static void
pcieadm_cap_info_fixed(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{
	*versp = &cap->ppc_vers[0];
	*lenp = cap->ppc_vers[0].ppr_len;
	*subcap = NULL;
}

static void
pcieadm_cap_info_vers(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{
	uint8_t vers;

	*subcap = NULL;
	vers = walkp->pcw_data->pcb_u8[off + 2] & 0xf;
	for (uint32_t i = 0; i < ARRAY_SIZE(cap->ppc_vers); i++) {
		if (vers == cap->ppc_vers[i].ppr_vers &&
		    cap->ppc_vers[i].ppr_vers != 0) {
			*versp = &cap->ppc_vers[i];
			*lenp = cap->ppc_vers[i].ppr_len;
			return;
		}
	}

	*versp = NULL;
	*lenp = 0;
}

/*
 * The PCI Power Management capability uses a 3-bit version ID as opposed to the
 * standard 4-bit version.
 */
static void
pcieadm_cap_info_pcipm(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{
	uint8_t vers;

	*subcap = NULL;
	vers = walkp->pcw_data->pcb_u8[off + 2] & 0x7;
	for (uint32_t i = 0; i < ARRAY_SIZE(cap->ppc_vers); i++) {
		if (vers == cap->ppc_vers[i].ppr_vers) {
			*versp = &cap->ppc_vers[i];
			*lenp = cap->ppc_vers[i].ppr_len;
			return;
		}
	}

	*versp = NULL;
	*lenp = 0;
}

/*
 * The PCIe capability underwent a few changes. In version 1 of the capability,
 * devices were not required to implement the entire capability. In particular,
 * endpoints did not need to implement anything more than the link status
 * register. In the v2 capability, this was changed such that all devices had to
 * implement the entire capbility, but otherwise hardcode registers to zero. As
 * such we get to play guess the length based on the device type.
 */
static const pcieadm_cap_vers_t pcieadm_cap_vers_pcie_v1_dev = {
	1, 0x0c, pcieadm_cap_pcie_v1_dev
};

static const pcieadm_cap_vers_t pcieadm_cap_vers_pcie_v1_link = {
	1, 0x14, pcieadm_cap_pcie_v1_link
};

static const pcieadm_cap_vers_t pcieadm_cap_vers_pcie_v1_slot = {
	1, 0x1c, pcieadm_cap_pcie_v1_slot
};

static const pcieadm_cap_vers_t pcieadm_cap_vers_pcie_v1_all = {
	1, 0x24, pcieadm_cap_pcie_v1_all
};

static const pcieadm_cap_vers_t pcieadm_cap_vers_pcie_v2 = {
	2, 0x4c, pcieadm_cap_pcie_v2
};

static void
pcieadm_cap_info_pcie(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{
	uint8_t vers = walkp->pcw_data->pcb_u8[off + 2] & 0xf;
	uint16_t pcie = walkp->pcw_data->pcb_u8[off + 2] |
	    (walkp->pcw_data->pcb_u8[off + 3] << 8);

	/*
	 * Version 2 is simple. There's only one thing to do, so we do it. For
	 * version 1 we need to look at the device type.
	 */
	*subcap = NULL;
	if (vers == 2) {
		*versp = &pcieadm_cap_vers_pcie_v2;
		*lenp = (*versp)->ppr_len;
		return;
	} else if (vers != 1) {
		*versp = NULL;
		*lenp = 0;
		return;
	}

	switch (pcie & PCIE_PCIECAP_DEV_TYPE_MASK) {
	case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
	case PCIE_PCIECAP_DEV_TYPE_PCI_DEV:
		*versp = &pcieadm_cap_vers_pcie_v1_link;
		break;
	case PCIE_PCIECAP_DEV_TYPE_RC_IEP:
		*versp = &pcieadm_cap_vers_pcie_v1_dev;
		break;
	case PCIE_PCIECAP_DEV_TYPE_UP:
	case PCIE_PCIECAP_DEV_TYPE_DOWN:
	case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
	case PCIE_PCIECAP_DEV_TYPE_PCI2PCIE:
		if ((pcie & PCIE_PCIECAP_SLOT_IMPL) != 0) {
			*versp = &pcieadm_cap_vers_pcie_v1_slot;
		} else {
			*versp = &pcieadm_cap_vers_pcie_v1_link;
		}
		break;
	case PCIE_PCIECAP_DEV_TYPE_ROOT:
	case PCIE_PCIECAP_DEV_TYPE_RC_EC:
		*versp = &pcieadm_cap_vers_pcie_v1_all;
		break;
	default:
		*versp = NULL;
		*lenp = 0;
		return;
	}

	*lenp = (*versp)->ppr_len;
}

/*
 * The length of the MSI capability depends on bits in its control field. As
 * such we use a custom function to extract the length and treat each of these
 * variants as thought it were a different version.
 */
static pcieadm_cap_vers_t pcieadm_cap_vers_msi_32 = {
	0, 0xa, pcieadm_cap_msi_32
};

static pcieadm_cap_vers_t pcieadm_cap_vers_msi_32ext = {
	0, 0xc, pcieadm_cap_msi_32ext
};

static pcieadm_cap_vers_t pcieadm_cap_vers_msi_64 = {
	0, 0xe, pcieadm_cap_msi_64
};

static pcieadm_cap_vers_t pcieadm_cap_vers_msi_64ext = {
	0, 0x10, pcieadm_cap_msi_64ext
};

static pcieadm_cap_vers_t pcieadm_cap_vers_msi_32pvm = {
	0, 0x14, pcieadm_cap_msi_32pvm
};

static pcieadm_cap_vers_t pcieadm_cap_vers_msi_64pvm = {
	0, 0x18, pcieadm_cap_msi_64pvm
};

static void
pcieadm_cap_info_msi(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{
	uint16_t ctrl;
	boolean_t addr64, pvm, ext;

	*subcap = NULL;
	ctrl = walkp->pcw_data->pcb_u8[off + 2] |
	    (walkp->pcw_data->pcb_u8[off + 3] << 8);
	if (ctrl == PCI_EINVAL16) {
		warnx("failed to read MSI Message Control register");
		*lenp = 0;
		*versp = NULL;
		return;
	}

	/*
	 * The MSI capability has three main things that control its size.
	 * 64-bit addressing adds 4 bytes. Per-Vector Masking adds 8 bytes and
	 * causes the Extended data addressing piece to always be present.
	 * Therefore we check first for pvm as it implies evt, effectively.
	 */
	addr64 = (ctrl & PCI_MSI_64BIT_MASK) != 0;
	pvm = (ctrl & PCI_MSI_PVM_MASK) != 0;
	ext = (ctrl & PCI_MSI_EMD_MASK) != 0;

	if (pvm && addr64) {
		*versp = &pcieadm_cap_vers_msi_64pvm;
	} else if (pvm) {
		*versp = &pcieadm_cap_vers_msi_32pvm;
	} else if (addr64 && ext) {
		*versp = &pcieadm_cap_vers_msi_64ext;
	} else if (addr64) {
		*versp = &pcieadm_cap_vers_msi_64;
	} else if (ext) {
		*versp = &pcieadm_cap_vers_msi_32ext;
	} else {
		*versp = &pcieadm_cap_vers_msi_32;
	}

	*lenp = (*versp)->ppr_len;
}

/*
 * The AER Capability is technically different for PCIe-PCI bridges. If we find
 * that device type here, then we need to use a different version information
 * rather than the actual set defined with the device (which have changed over
 * time).
 */
static const pcieadm_cap_vers_t pcieadm_cap_vers_aer_bridge = {
	1, 0x4c, pcieadm_cap_aer_bridge
};

static void
pcieadm_cap_info_aer(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{
	if (walkp->pcw_pcietype == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		uint8_t vers;

		*subcap = NULL;
		vers = walkp->pcw_data->pcb_u8[off + 2] & 0xf;
		if (vers != pcieadm_cap_vers_aer_bridge.ppr_vers) {
			warnx("encountered PCIe to PCI bridge with unknown "
			    "AER capability version: %u", vers);
			*lenp = 0;
			*versp = NULL;
			return;
		}
		*lenp = pcieadm_cap_vers_aer_bridge.ppr_len;
		*versp = &pcieadm_cap_vers_aer_bridge;
	}

	return (pcieadm_cap_info_vers(walkp, cap, off, versp, lenp, subcap));
}

/*
 * The PCI-X capability varies depending on the header type of the device.
 * Therefore we simply use the device type to figure out what to do.
 */
static pcieadm_cap_vers_t pcieadm_cap_vers_pcix_dev = {
	0, 0x8, pcieadm_cap_pcix_dev
};

static pcieadm_cap_vers_t pcieadm_cap_vers_pcix_bridge = {
	0, 0x10, pcieadm_cap_pcix_bridge
};

static void
pcieadm_cap_info_pcix(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{

	*subcap = NULL;
	switch (walkp->pcw_dtype) {
	case PCI_HEADER_ZERO:
		*versp = &pcieadm_cap_vers_pcix_dev;
		break;
	case PCI_HEADER_ONE:
		*versp = &pcieadm_cap_vers_pcix_bridge;
		break;
	default:
		warnx("encountered PCI-X capability with unsupported device "
		    "type: 0x%x\n", walkp->pcw_dtype);
		*lenp = 0;
		*versp = NULL;
		return;
	}

	*lenp = (*versp)->ppr_len;
}

typedef struct pcieadm_cap_ht {
	uint32_t pch_capid;
	pcieadm_subcap_t pch_subcap;
	pcieadm_cap_vers_t pch_vers;
} pcieadm_cap_ht_t;

static pcieadm_cap_ht_t pcieadm_ht_cap_pri = {
	0x00, { "pri", "Primary" }, { 0, 0x1c, pcieadm_cap_ht_pri }
};

static pcieadm_cap_ht_t pcieadm_ht_cap_sec = {
	0x01, { "sec", "Secondary" }, { 0, 0x18, pcieadm_cap_ht_sec }
};

static pcieadm_cap_ht_t pcieadm_ht_caps[] = {
	{ 0x08, { "switch", "Switch" } },
	{ 0x10, { "intr", "Interrupt Discovery and Configuration" },
	    { 0, 8, pcieadm_cap_ht_intr } },
	{ 0x11, { "rev", "Revision ID" } },
	{ 0x12, { "unitid", "UnitID Clumping" } },
	{ 0x13, { "extcfg", "Extended Configuration Space Access" } },
	{ 0x14, { "addrmap", "Address Mapping" } },
	{ 0x15, { "msi", "MSI Mapping" },
	    { 0, 4, pcieadm_cap_ht_msi } },
	{ 0x16, { "dir", "DirectRoute" } },
	{ 0x17, { "vcset", "VCSet" } },
	{ 0x18, { "retry", "Retry Mode" } },
	{ 0x19, { "x86", "X86 Encoding" } },
	{ 0x1a, { "gen3", "Gen3" } },
	{ 0x1b, { "fle", "Function-Level Extension" } },
	{ 0x1c, { "pm", "Power Management" } },
	{ UINT32_MAX, NULL },
};

static void
pcieadm_cap_info_ht(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_pci_cap_t *cap, uint32_t off,
    const pcieadm_cap_vers_t **versp, uint32_t *lenp,
    const pcieadm_subcap_t **subcap)
{
	uint32_t base = walkp->pcw_data->pcb_u32[off / 4];
	uint32_t caplo = bitx32(base, 31, 29);
	pcieadm_cap_ht_t *htcap = NULL;

	*versp = NULL;
	*lenp = 0;
	*subcap = NULL;

	if (caplo > 1) {
		uint32_t capid = bitx32(base, 31, 27);

		for (uint32_t i = 0; pcieadm_ht_caps[i].pch_capid != UINT32_MAX;
		    i++) {
			if (capid == pcieadm_ht_caps[i].pch_capid) {
				htcap = &pcieadm_ht_caps[i];
				break;
			}
		}
	} else if (caplo == 0) {
		htcap = &pcieadm_ht_cap_pri;
	} else if (caplo == 1) {
		htcap = &pcieadm_ht_cap_sec;
	}

	if (htcap == NULL) {
		warnx("encountered unknown HyperTransport Capability 0x%x",
		    bitx32(base, 31, 27));
		return;
	}

	*subcap = &htcap->pch_subcap;
	if (htcap->pch_vers.ppr_print != NULL) {
		*versp = &htcap->pch_vers;
		*lenp = htcap->pch_vers.ppr_len;
	}
}

/*
 * Root Complex Link Declaration
 */
static const pcieadm_regdef_t pcieadm_regdef_rcld_desc[] = {
	{ 0, 3, "type", "Element Type", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "Configuration Space Element",
	    "System Egress Port or internal sink",
	    "Internal Root Complex Link" } } },
	{ 8, 15, "num", "Number of Entries", PRDV_HEX },
	{ 16, 23, "id", "Component ID", PRDV_HEX },
	{ 24, 31, "port", "Port Number", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_rcld_link[] = {
	{ 0, 0, "valid", "Link Valid", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 1, 1, "type", "Link Type", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "RCRB", "Configuration Space" } } },
	{ 2, 2, "rcrb", "Assosciate RCRB", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 16, 23, "tid", "Target Component ID", PRDV_HEX },
	{ 24, 31, "tport", "Target Port Number", PRDV_HEX },
	{ -1, -1, NULL }
};

/*
 * Print a variable number of Root Complex Links.
 */
static void
pcieadm_cfgspace_print_rcld(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint_t nlinks = walkp->pcw_data->pcb_u8[walkp->pcw_capoff + 5];

	for (uint_t i = 0; i < nlinks; i++) {
		char mshort[32], mhuman[128];
		pcieadm_cfgspace_print_t p;
		uint16_t off = print->pcp_off + i * 0x10;
		uint8_t type = walkp->pcw_data->pcb_u8[walkp->pcw_capoff + off];

		(void) snprintf(mshort, sizeof (mshort), "link%udesc", i);
		(void) snprintf(mhuman, sizeof (mhuman), "Link %u Description");

		p.pcp_off = off;
		p.pcp_len = 4;
		p.pcp_short = mshort;
		p.pcp_human = mhuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_rcld_link;

		p.pcp_print(walkp, &p, p.pcp_arg);

		/*
		 * The way that we print the link depends on the actual type of
		 * link which is in bit 2 of the link description.
		 */
		p.pcp_off += 8;

		if ((type & (1 << 1)) == 0) {
			(void) snprintf(mshort, sizeof (mshort),
			    "link%uaddr", i);
			(void) snprintf(mhuman, sizeof (mhuman),
			    "Link %u Address");
			p.pcp_len = 8;
			p.pcp_print = pcieadm_cfgspace_print_hex;
			p.pcp_arg = NULL;

			p.pcp_print(walkp, &p, p.pcp_arg);
		} else {
			warnx("encountered unsupported RCLD Link Address");
		}
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_rcld[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "desc", "Self Description",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_rcld_desc },
	{ 0x10, 0x10, "link", "Link Entry", pcieadm_cfgspace_print_rcld },
	{ -1, -1, NULL }
};


/*
 * Physical Layer 32.0 GT/s Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_32g_cap[] = {
	{ 0, 0, "eqbyp", "Equalization Bypass to Highest Rate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "noeq", "No Equalization Needed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "mts0", "Modified TS Usage Mode 0 - PCI Express", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 9, 9, "mts1", "Modified TS Usage Mode 1 - Training Set", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 10, 10, "mts2", "Modified TS Usage Mode 2 - Alternate Protocol",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "unsupported",
	    "supported" } } },
	/*
	 * Bits 11 to 15 are defined as reserved for future use here as
	 * read-only bits. Add them here once they have actual definitions.
	 */
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_32g_ctl[] = {
	{ 0, 0, "eqbyp", "Equalization Bypass to Highest Rate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "enabled", "disabled" } } },
	{ 1, 1, "noeq", "No Equalization Needed", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "enabled", "disabled" } } },
	{ 8, 10, "mts", "Modified TS Usage Mode Selected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "PCIe", "training set messages",
	    "alternate protocol negotiation" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_32g_sts[] = {
	{ 0, 0, "eqcomp", "Equalization 32.0 GT/s Complete", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 1, 1, "eqp1", "Equalization 32.0 GT/s Phase 1", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 2, 2, "eqp2", "Equalization 32.0 GT/s Phase 2", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 3, 3, "eqp3", "Equalization 32.0 GT/s Phase 3", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "incomplete", "complete" } } },
	{ 4, 4, "req", "Link Equalization Request 32.0 GT/s", PRDV_HEX },
	{ 5, 5, "mts", "Modified TS Received", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 6, 7, "rxelbc", "Received Enhanced Link Behavior Control",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = {
	    "full equalization required", "equalization bypass to highest rate",
	    "no equalization needed", "modified TS1/TS2 ordered sets" } } },
	{ 8, 8, "txpre", "Transmitter Precoding", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 9, 9, "prereq", "Transmitter Precoding Request", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 10, 10, "noeqrx", "No Equalization Needed Received", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_32g_rxts1[] = {
	{ 0, 2, "mts", "Modified TS Usage Mode Selected", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "PCIe", "training set messages",
	    "alternate protocol negotiation" } } },
	{ 3, 15, "info", "Received Modified TS Information 1", PRDV_HEX },
	{ 16, 31, "vendor", "Received Modified TS Vendor ID", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_32g_rxts2[] = {
	{ 0, 23, "info", "Received Modified TS Information 2", PRDV_HEX },
	{ 24, 25, "apnsts", "Alternate Protocol Negotiation Status",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "not supported",
	    "disabled", "failed", "succeeded" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_32g_txts1[] = {
	{ 0, 2, "mts", "Transmitted Modified TS Usage Mode", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "PCIe", "training set messages",
	    "alternate protocol negotiation" } } },
	{ 3, 15, "info", "Transmitted Modified TS Information 1", PRDV_HEX },
	{ 16, 31, "vendor", "Transmitted Modified TS Vendor ID", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_32g_txts2[] = {
	{ 0, 23, "info", "Transmitted Modified TS Information 2", PRDV_HEX },
	{ 24, 25, "apnsts", "Alternate Protocol Negotiation Status",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "not supported",
	    "disabled", "failed", "succeeded" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_32g_eq[] = {
	{ 0, 3, "dstxpre", "Downstream Port 32.0 GT/s Transmitter Preset",
	    PRDV_HEX },
	{ 4, 7, "ustxpre", "Upstream Port 32.0 GT/s Transmitter Preset",
	    PRDV_HEX },
	{ -1, -1, NULL }
};

static void
pcieadm_cfgspace_print_32geq(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	if (walkp->pcw_nlanes == 0) {
		warnx("failed to capture lane count, but somehow have "
		    "Physical Layer 32.0 GT/s cap");
		return;
	}

	for (uint_t i = 0; i < walkp->pcw_nlanes; i++) {
		char eqshort[32], eqhuman[128];
		pcieadm_cfgspace_print_t p;

		(void) snprintf(eqshort, sizeof (eqshort), "lane%u", i);
		(void) snprintf(eqhuman, sizeof (eqhuman), "Lane %u EQ Control",
		    i);
		p.pcp_off = print->pcp_off + i * 1;
		p.pcp_len = 1;
		p.pcp_short = eqshort;
		p.pcp_human = eqhuman;
		p.pcp_print = pcieadm_cfgspace_print_regdef;
		p.pcp_arg = pcieadm_regdef_32g_eq;

		p.pcp_print(walkp, &p, p.pcp_arg);
	}
}

static const pcieadm_cfgspace_print_t pcieadm_cap_32g[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "32.0 GT/s Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_32g_cap },
	{ 0x8, 4, "ctl", "32.0 GT/s Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_32g_ctl },
	{ 0xc, 4, "sts", "32.0 GT/s Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_32g_sts },
	{ 0x10, 4, "rxts1", "Received Modified TS Data 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_32g_rxts1 },
	{ 0x14, 4, "rxts2", "Received Modified TS Data 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_32g_rxts2 },
	{ 0x18, 4, "txts1", "Transmitted Modified TS Data 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_32g_txts1 },
	{ 0x1c, 4, "txts2", "Transmitted Modified TS Data 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_32g_txts2 },
	{ 0x20, 1, "eqctl", "32.0 GT/s EQ Control",
	    pcieadm_cfgspace_print_32geq },
	{ -1, -1, NULL }
};

/*
 * Native PCIe Enclosure Management
 */
static const pcieadm_regdef_t pcieadm_regdef_npem_cap[] = {
	{ 0, 0, "npem", "NPEM", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 1, 1, "reset", "NPEM Reset", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 2, 2, "ok", "NPEM OK", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 3, 3, "loc", "NPEM Locate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 4, 4, "fail", "NPEM Fail", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 5, 5, "rb", "NPEM Rebuild", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 6, 6, "pfa", "NPEM PFA", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 7, 7, "hs", "NPEM Hot Spare", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 8, 8, "crit", "NPEM In a Critical Array", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 9, 9, "fail", "NPEM In a Failed Array", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 10, 10, "invdt", "NPEM Invalid Device type", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 11, 11, "dis", "NPEM Disabled", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ 24, 31, "es", "Enclosure-specific Capabilities", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_npem_ctl[] = {
	{ 0, 0, "npem", "NPEM", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 1, "reset", "NPEM Initiate Reset", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 2, 2, "ok", "NPEM OK", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 3, 3, "loc", "NPEM Locate", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 4, 4, "fail", "NPEM Fail", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 5, 5, "rb", "NPEM Rebuild", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 6, 6, "pfa", "NPEM PFA", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 7, 7, "hs", "NPEM Hot Spare", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 8, 8, "crit", "NPEM In a Critical Array", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 9, 9, "fail", "NPEM In a Failed Array", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 10, 10, "invdt", "NPEM Invalid Device type", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 11, 11, "dis", "NPEM Disabled", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 24, 31, "es", "Enclosure-specific Control", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_npem_sts[] = {
	{ 0, 0, "ccmplt", "NPEM Command Complete", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "no", "yes" } } },
	{ 24, 31, "es", "Enclosure-specific Status", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_npem[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "NPEM Capability",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_npem_cap },
	{ 0x8, 4, "ctl", "NPEM Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_npem_ctl },
	{ 0xc, 4, "sts", "NPEM Status",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_npem_sts },
	{ -1, -1, NULL }
};

/*
 * Alternate Protocol Capability
 */
static const pcieadm_regdef_t pcieadm_regdef_ap_cap[] = {
	{ 0, 7, "count", "Alternate Protocol Count", PRDV_HEX },
	{ 8, 8, "sen", "Alternate Protocol Select Enable", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "unsupported", "supported" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ap_ctl[] = {
	{ 0, 7, "index", "Alternate Protocol Index Select", PRDV_HEX },
	{ 8, 8, "apngen", "Alternate Protocol Negotiation Global Enable",
	    PRDV_STRVAL, .prd_val = { .prdv_strval = { "disabled",
	    "enabled" } } },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ap_data1[] = {
	{ 0, 2, "use", "Alternate Protocol Usage Information", PRDV_HEX },
	{ 5, 15, "detail", "Alternate Protocol Details", PRDV_HEX },
	{ 16, 31, "vendor", "Alternate Protocol Vendor ID", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ap_data2[] = {
	{ 0, 23, "mts2", "Modified TS 2 Information", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_regdef_t pcieadm_regdef_ap_sen[] = {
	{ 0, 0, "pcie", "Selective Enable Mask - PCIe", PRDV_STRVAL,
	    .prd_val = { .prdv_strval = { "disabled", "enabled" } } },
	{ 1, 31, "other", "Selective Enable Mask - Other", PRDV_HEX },
	{ -1, -1, NULL }
};

/*
 * The Advanced Protocol Selective Enable Mask register is only present if a bit
 * in the capabilities register is present. As such, we need to check if it is
 * here before we try to read and print it.
 */
static void
pcieadm_cfgspace_print_ap_sen(pcieadm_cfgspace_walk_t *walkp,
    const pcieadm_cfgspace_print_t *print, const void *arg)
{
	uint32_t ap_cap = walkp->pcw_data->pcb_u32[walkp->pcw_capoff + 4];
	pcieadm_cfgspace_print_t p;

	if (bitx32(ap_cap, 8, 8) == 0)
		return;

	(void) memcpy(&p, print, sizeof (*print));
	p.pcp_print = pcieadm_cfgspace_print_regdef;
	p.pcp_arg = pcieadm_regdef_ap_sen;

	p.pcp_print(walkp, &p, p.pcp_arg);
}

static const pcieadm_cfgspace_print_t pcieadm_cap_ap[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "cap", "Alternate Protocol Capabilities",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ap_cap },
	{ 0x8, 4, "ctl", "Alternate Protocol Control",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ap_ctl },
	{ 0xc, 4, "data1", "Alternate Protocol Data 1",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ap_data1 },
	{ 0x10, 4, "data2", "Alternate Protocol Data 2",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_ap_data2 },
	{ 0x14, 4, "sen", "Alternate Protocol Select Enable Mask",
	    pcieadm_cfgspace_print_ap_sen },
	{ -1, -1, NULL }
};

/*
 * Root Complex Event Collector Endpoint Association
 */
static const pcieadm_regdef_t pcieadm_regdef_rcecea_bus[] = {
	{ 8, 15, "next", "RCEC Next Bus", PRDV_HEX },
	{ 16, 23, "last", "RCEC Last Bus", PRDV_HEX },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_rcecea_v1[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "bitmap", "Association Bitmap for RCiEPs",
	    pcieadm_cfgspace_print_hex },
	{ -1, -1, NULL }
};

static const pcieadm_cfgspace_print_t pcieadm_cap_rcecea_v2[] = {
	{ 0x0, 4, "caphdr", "Capability Header",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_pcie_caphdr },
	{ 0x4, 4, "bitmap", "Association Bitmap for RCiEPs",
	    pcieadm_cfgspace_print_hex },
	{ 0x8, 4, "bus", "RCEC Associated Bus Numbers",
	    pcieadm_cfgspace_print_regdef, pcieadm_regdef_rcecea_bus },
	{ -1, -1, NULL }
};

static const pcieadm_pci_cap_t pcieadm_pci_caps[] = {
	{ PCI_CAP_ID_PM, "pcipm", "PCI Power Management",
	    pcieadm_cap_info_pcipm, { { 2, 8, pcieadm_cap_pcipm_v3 },
	    { 3, 8, pcieadm_cap_pcipm_v3 } } },
	{ PCI_CAP_ID_AGP, "agp", "Accelerated Graphics Port" },
	{ PCI_CAP_ID_VPD, "vpd", "Vital Product Data", pcieadm_cap_info_fixed,
	    { { 0, 8, pcieadm_cap_vpd } } },
	{ PCI_CAP_ID_SLOT_ID, "slot", "Slot Identification" },
	{ PCI_CAP_ID_MSI, "msi", "Message Signaled Interrupts",
	    pcieadm_cap_info_msi },
	{ PCI_CAP_ID_cPCI_HS, "cpci", "CompactPCI Hot Swap" },
	{ PCI_CAP_ID_PCIX, "pcix", "PCI-X", pcieadm_cap_info_pcix },
	{ PCI_CAP_ID_HT, "ht", "HyperTransport", pcieadm_cap_info_ht },
	{ PCI_CAP_ID_VS, "vs", "Vendor Specific", pcieadm_cap_info_fixed,
	    { { 0, 3, pcieadm_cap_vs } } },
	{ PCI_CAP_ID_DEBUG_PORT, "dbg", "Debug Port", pcieadm_cap_info_fixed,
	    { { 0, 4, pcieadm_cap_debug } } },
	{ PCI_CAP_ID_cPCI_CRC, "cpcicrc",
	    "CompactPCI Central Resource Control" },
	{ PCI_CAP_ID_PCI_HOTPLUG, "pcihp", "PCI Hot-Plug" },
	{ PCI_CAP_ID_P2P_SUBSYS, "bdgsub", "PCI Bridge Subsystem Vendor ID",
	    pcieadm_cap_info_fixed, { 0, 8, pcieadm_cap_bridge_subsys } },
	{ PCI_CAP_ID_AGP_8X, "agp8x", "AGP 8x" },
	{ PCI_CAP_ID_SECURE_DEV, "secdev", "Secure Device" },
	{ PCI_CAP_ID_PCI_E, "pcie", "PCI Express", pcieadm_cap_info_pcie },
	{ PCI_CAP_ID_MSI_X, "msix", "MSI-X", pcieadm_cap_info_fixed,
	    { { 0, 12, pcieadm_cap_msix } } },
	{ PCI_CAP_ID_SATA, "sata", "Serial ATA Configuration",
	    pcieadm_cap_info_fixed, { { 0, 8, pcieadm_cap_sata } } },
	/*
	 * Note, the AF feature doesn't have a version but encodes a length in
	 * the version field, so we cheat and use that.
	 */
	{ PCI_CAP_ID_FLR, "af", "Advanced Features", pcieadm_cap_info_vers,
	    { { 6, 6, pcieadm_cap_af } } },
	{ PCI_CAP_ID_EA, "ea", "Enhanced Allocation" },
	{ PCI_CAP_ID_FPB, "fpb", "Flattening Portal Bridge" }
};

static const pcieadm_pci_cap_t pcieadm_pcie_caps[] = {
	{ 0, "null", "NULL Capability", pcieadm_cap_info_fixed,
	    { { 0, 0x4, pcieadm_cap_null } } },
	{ PCIE_EXT_CAP_ID_AER, "aer", "Advanced Error Reporting",
	    pcieadm_cap_info_aer, { { 1, 0x38, pcieadm_cap_aer_v1 },
	    { 2, 0x48, pcieadm_cap_aer_v2 } } },
	{ PCIE_EXT_CAP_ID_VC, "vc", "Virtual Channel", pcieadm_cap_info_vers,
	    { { 0x1, 0x1c, pcieadm_cap_vc } } },
	{ PCIE_EXT_CAP_ID_SER, "sn", "Serial Number", pcieadm_cap_info_vers,
	    { { 1, 0xc, pcieadm_cap_sn } } },
	{ PCIE_EXT_CAP_ID_PWR_BUDGET, "pwrbudg", "Power Budgeting",
	    pcieadm_cap_info_vers, { { 1, 0x10, pcieadm_cap_powbudg } } },
	{ PCIE_EXT_CAP_ID_RC_LINK_DECL, "rcld",
	    "Root Complex Link Declaration",  pcieadm_cap_info_vers,
	    { { 1, 0x1c, pcieadm_cap_rcld } } },
	{ PCIE_EXT_CAP_ID_RC_INT_LINKCTRL, "rcilc",
	    "Root Complex Internal Link Control" },
	{ PCIE_EXT_CAP_ID_RC_EVNT_CEA, "rcecea",
	    "Root Complex Event Collector Endpoint Association",
	    pcieadm_cap_info_vers, { { 1, 0x8, pcieadm_cap_rcecea_v1 },
	    { 2, 0xc, pcieadm_cap_rcecea_v2 } } },
	{ PCIE_EXT_CAP_ID_MFVC, "mfvc", "Multi-Function Virtual Channel" },
	{ PCIE_EXT_CAP_ID_VC_WITH_MFVC, "vcwmfvc", "Virtual Channel with MFVC",
	    pcieadm_cap_info_vers, { { 0x1, 0x1c, pcieadm_cap_vc } } },
	{ PCIE_EXT_CAP_ID_RCRB, "rcrb", "Root Complex Register Block" },
	{ PCIE_EXT_CAP_ID_VS, "vsec", "Vendor Specific Extended Capability",
	    pcieadm_cap_info_vers, { { 1, 0x8, pcieadm_cap_vsec } } },
	{ PCIE_EXT_CAP_ID_CAC, "cac", "Configuration Access Correlation" },
	{ PCIE_EXT_CAP_ID_ACS, "acs", "Access Control Services",
	    pcieadm_cap_info_vers, { { 1, 0x8, pcieadm_cap_acs } } },
	{ PCIE_EXT_CAP_ID_ARI, "ari", "Alternative Routing-ID Interpretation",
	    pcieadm_cap_info_vers, { { 1, 0x8, pcieadm_cap_ari } } },
	{ PCIE_EXT_CAP_ID_ATS, "ats", "Access Translation Services",
	    pcieadm_cap_info_vers, { { 1, 0x8, pcieadm_cap_ats } } },
	{ PCIE_EXT_CAP_ID_SRIOV, "sriov", "Single Root I/O Virtualization",
	    pcieadm_cap_info_vers, { { 1, 0x40, pcieadm_cap_sriov } } },
	{ PCIE_EXT_CAP_ID_MRIOV, "mriov", "Multi-Root I/O Virtualization" },
	{ PCIE_EXT_CAP_ID_MULTICAST, "mcast", "Multicast",
	    pcieadm_cap_info_vers, { { 1, 0x30, pcieadm_cap_mcast } } },
	{ PCIE_EXT_CAP_ID_PGREQ, "pgreq", "Page Request",
	    pcieadm_cap_info_vers, { { 1, 0x10, pcieadm_cap_pgreq } } },
	{ PCIE_EXT_CAP_ID_EA, "ea", "Enhanced Allocation" },
	{ PCIE_EXT_CAP_ID_RESIZE_BAR, "rbar", "Resizable Bar" },
	{ PCIE_EXT_CAP_ID_DPA, "dpa", "Dynamic Power Allocation",
	    pcieadm_cap_info_vers, { { 1, 0x10, pcieadm_cap_dpa } } },
	{ PCIE_EXT_CAP_ID_TPH_REQ, "tph", "TPH Requester",
	    pcieadm_cap_info_vers, { { 1, 0xc, pcieadm_cap_tph } } },
	{ PCIE_EXT_CAP_ID_LTR, "ltr", "Latency Tolerance Reporting",
	    pcieadm_cap_info_vers, { { 1, 0x8, pcieadm_cap_ltr } } },
	{ PCIE_EXT_CAP_ID_PCIE2, "pcie2", "Secondary PCI Express",
	    pcieadm_cap_info_vers, { { 1, 0xc, pcieadm_cap_pcie2 } } },
	{ PCIE_EXT_CAP_ID_PASID, "pasid", "Process Address Space ID",
	    pcieadm_cap_info_vers, { { 1, 0x8, pcieadm_cap_pasid } } },
	{ PCIE_EXT_CAP_ID_LNR, "lnr", "LN Requester" },
	{ PCIE_EXT_CAP_ID_DPC, "dpc", "Downstream Port Containment",
	    pcieadm_cap_info_vers, { { 1, 0x30, pcieadm_cap_dpc } } },
	{ PCIE_EXT_CAP_ID_L1PM, "l1pm", "L1 PM Substates",
	    pcieadm_cap_info_vers, { { 1, 0x10, pcieadm_cap_l1pm_v1 },
	    { 2, 0x14, pcieadm_cap_l1pm_v2 } } },
	{ PCIE_EXT_CAP_ID_PTM, "ptm", "Precision Time Management",
	    pcieadm_cap_info_vers, { { 1, 0xc, pcieadm_cap_info_ptm } } },
	{ PCIE_EXT_CAP_ID_FRS, "frs", "FRS Queueing" },
	{ PCIE_EXT_CAP_ID_RTR, "trt", "Readiness Time Reporting" },
	/*
	 * When we encounter a designated vendor specification, in particular,
	 * for CXL, we'll want to set ppc_subcap so we can use reasonable
	 * filtering.
	 */
	{ PCIE_EXT_CAP_ID_DVS, "dvsec",
	    "Designated Vendor-Specific Extended Capability" },
	{ PCIE_EXT_CAP_ID_VFRBAR, "vfrbar", "Virtual Function Resizable BAR" },
	{ PCIE_EXT_CAP_ID_DLF, "dlf", "Data Link Feature",
	    pcieadm_cap_info_vers, { { 1, 0xc, pcieadm_cap_dlf } } },
	{ PCIE_EXT_CAP_ID_PL16GT, "pl16g", "Physical Layer 16.0 GT/s",
	    pcieadm_cap_info_vers, { { 1, 0x22, pcieadm_cap_16g } } },
	{ PCIE_EXT_CAP_ID_LANE_MARGIN, "margin",
	    "Lane Margining at the Receiver", pcieadm_cap_info_vers,
	    { { 1, 0x8, pcieadm_cap_margin } } },
	{ PCIE_EXT_CAP_ID_HIEARCHY_ID, "hierid", "Hierarchy ID" },
	{ PCIE_EXT_CAP_ID_NPEM, "npem", "Native PCIe Enclosure Management",
	    pcieadm_cap_info_vers, { { 1, 0x10, pcieadm_cap_npem } } },
	/*
	 * The sizing of the 32.0 GT/s physical layer requires that there's at
	 * least one lane's worth of information and the device is required to
	 * pad that out to 4-byte alignment.
	 */
	{ PCIE_EXT_CAP_ID_PL32GT, "pl32g", "Physical Layer 32.0 GT/s",
	    pcieadm_cap_info_vers, { { 1, 0x24, pcieadm_cap_32g } } },
	{ PCIE_EXT_CAP_ID_AP, "ap", "Alternative Protocol",
	    pcieadm_cap_info_vers, { { 1, 0x14, pcieadm_cap_ap } } },
	{ PCIE_EXT_CAP_ID_SFI, "sfi", "System Firmware Intermediary" },
	{ PCIE_EXT_CAP_ID_SHDW_FUNC, "sfunc", "Shadow Functions" },
	{ PCIE_EXT_CAP_ID_DOE, "doe", "Data Object Exchange" },
	{ PCIE_EXT_CAP_ID_DEV3, "dev3", "Device 3" },
	{ PCIE_EXT_CAP_ID_IDE, "ide", "Integrity and Data Encryption" },
	{ PCIE_EXT_CAP_ID_PL64GT, "pl64g", "Physical Layer 64.0 GT/s" },
	{ PCIE_EXT_CAP_ID_FLIT_LOG, "fltlog", "Flit Logging" },
	{ PCIE_EXT_CAP_ID_FLIT_PERF, "fltperf",
	    "Flit Performance Measurement" },
	{ PCIE_EXT_CAP_ID_FLIT_ERR, "flterr", "Flit Error Injection" },
	{ PCIE_EXT_CAP_ID_SVC, "svc", "Streamlined Virtual Channel" },
	{ PCIE_EXT_CAP_ID_MMIO_RBL, "mrbl", "MMIO Register Block Locator" }
};

static const pcieadm_pci_cap_t *
pcieadm_cfgspace_match_cap(uint32_t capid, boolean_t pcie)
{
	uint_t ncaps;
	const pcieadm_pci_cap_t *caps;

	if (pcie) {
		ncaps = ARRAY_SIZE(pcieadm_pcie_caps);
		caps = pcieadm_pcie_caps;
	} else {
		ncaps = ARRAY_SIZE(pcieadm_pci_caps);
		caps = pcieadm_pci_caps;
	}

	for (uint_t i = 0; i < ncaps; i++) {
		if (caps[i].ppc_id == capid) {
			return (&caps[i]);
		}
	}

	return (NULL);
}

static void
pcieadm_cfgspace_print_cap(pcieadm_cfgspace_walk_t *walkp, uint_t capid,
    const pcieadm_pci_cap_t *cap_info, const pcieadm_cap_vers_t *vers_info,
    const pcieadm_subcap_t *subcap)
{
	boolean_t filter = B_FALSE;

	/*
	 * If we don't recognize the capability, print out the ID if we're not
	 * filtering and not in parsable mode.
	 */
	if (cap_info == NULL) {
		if (walkp->pcw_ofmt == NULL &&
		    pcieadm_cfgspace_filter(walkp, NULL)) {
			warnx("encountered unknown capability ID 0x%x "
			    "unable to print or list", capid);
			pcieadm_print("Unknown Capability (0x%x)\n", capid);
		}
		return;
	}

	/*
	 * Check to see if we should print this and in particular, if there's
	 * both a capability or subcapability, we need to try and match both.
	 * The reason that the calls to check the filters are conditioned on
	 * pcw_ofmt is that when we're in parsable mode, we cannot match a
	 * top-level capability since it's an arbitrary number of fields.
	 */
	if (walkp->pcw_ofmt == NULL) {
		filter = pcieadm_cfgspace_filter(walkp, cap_info->ppc_short);
	}
	pcieadm_strfilt_push(walkp, cap_info->ppc_short);
	if (subcap != NULL) {
		if (walkp->pcw_ofmt == NULL) {
			boolean_t subfilt = pcieadm_cfgspace_filter(walkp,
			    subcap->psub_short);
			filter = subfilt || filter;
		}
		pcieadm_strfilt_push(walkp, subcap->psub_short);
	}


	if (walkp->pcw_ofmt == NULL && filter) {
		if ((walkp->pcw_flags & PCIEADM_CFGSPACE_F_SHORT) != 0) {
			if (subcap != NULL) {
				pcieadm_print("%s Capability - %s (%s) "
				    "(0x%x)\n", cap_info->ppc_human,
				    subcap->psub_human,
				    walkp->pcw_filt->pstr_curgen, capid);
			} else {
				pcieadm_print("%s Capability (%s) (0x%x)\n",
				    cap_info->ppc_human,
				    walkp->pcw_filt->pstr_curgen, capid);
			}
		} else {
			if (subcap != NULL) {
				pcieadm_print("%s Capability - %s (0x%x)\n",
				    cap_info->ppc_human, subcap->psub_human,
				    capid);
			} else {
				pcieadm_print("%s Capability (0x%x)\n",
				    cap_info->ppc_human, capid);
			}
		}
	}

	if (vers_info != NULL) {
		const pcieadm_cfgspace_print_t *print;

		pcieadm_indent();
		for (print = vers_info->ppr_print;
		    print->pcp_short != NULL; print++) {
			VERIFY3P(print->pcp_print, !=, NULL);
			print->pcp_print(walkp, print,
			    print->pcp_arg);
		}
		pcieadm_deindent();
	} else {
		if (subcap != NULL) {
			warnx("Unable to print or list %s - %s (no support or "
			    "missing version info)", cap_info->ppc_human,
			    subcap->psub_human);
		} else {
			warnx("Unable to print or list %s (no support or "
			    "missing version info)", cap_info->ppc_human);
		}
	}

	if (subcap != NULL) {
		pcieadm_strfilt_pop(walkp);
	}
	pcieadm_strfilt_pop(walkp);
}

static void
pcieadm_cfgspace_write(int fd, const uint8_t *source, size_t len)
{
	size_t off = 0;

	while (len > 0) {
		ssize_t ret = write(fd, source + off, len - off);
		if (ret < 0) {
			err(EXIT_FAILURE, "failed to write config space to "
			    "output file");
		}

		off += ret;
		len -= ret;
	}
}

void
pcieadm_cfgspace(pcieadm_t *pcip, pcieadm_cfgspace_op_t op,
    pcieadm_cfgspace_f readf, int fd, void *readarg, uint_t nfilts,
    pcieadm_cfgspace_filter_t *filters, pcieadm_cfgspace_flags_t flags,
    ofmt_handle_t ofmt)
{
	uint_t type;
	uint16_t cap;
	pcieadm_cfgspace_data_t data;
	pcieadm_cfgspace_walk_t walk;
	const char *headstr, *headshort;
	const pcieadm_cfgspace_print_t *header;
	boolean_t capsup = B_FALSE, extcfg = B_FALSE;
	uint_t ncaps;

	walk.pcw_pcieadm = pcip;
	walk.pcw_op = op;
	walk.pcw_data = &data;
	walk.pcw_outfd = fd;
	walk.pcw_capoff = 0;
	walk.pcw_nlanes = 0;
	walk.pcw_nfilters = nfilts;
	walk.pcw_filters = filters;
	walk.pcw_flags = flags;
	walk.pcw_ofmt = ofmt;
	walk.pcw_filt = NULL;

	/*
	 * Start by reading all of the basic 40-byte config space header in one
	 * fell swoop.
	 */
	for (uint32_t i = 0; i < PCI_CAP_PTR_OFF / 4; i++) {
		if (!readf(i * 4, 4, &data.pcb_u32[i], readarg)) {
			errx(EXIT_FAILURE, "failed to read offset %u from "
			    "configuration space", i * 4);
		}
	}
	walk.pcw_valid = PCI_CAP_PTR_OFF;
	walk.pcw_caplen = PCI_CAP_PTR_OFF;

	/*
	 * Grab the information from the header that we need to figure out what
	 * kind of device this is, how to print it, if there are any
	 * capabilities, and go from there.
	 */
	type = data.pcb_u8[PCI_CONF_HEADER] & PCI_HEADER_TYPE_M;
	switch (type) {
	case PCI_HEADER_ZERO:
		headstr = "Type 0 Header";
		headshort = "header0";
		header = pcieadm_cfgspace_type0;
		capsup = (data.pcb_u8[PCI_CONF_STAT] & PCI_STAT_CAP) != 0;
		break;
	case PCI_HEADER_ONE:
		headstr = "Type 1 Header";
		headshort = "header1";
		header = pcieadm_cfgspace_type1;
		capsup = (data.pcb_u8[PCI_CONF_STAT] & PCI_STAT_CAP) != 0;
		break;
	case PCI_HEADER_TWO:
	default:
		headstr = "Unknown Header";
		headshort = "headerX";
		header = pcieadm_cfgspace_unknown;
		warnx("unsupported PCI header type: 0x%x, output limited to "
		    "data configuration space");
	}

	walk.pcw_dtype = type;

	if (op == PCIEADM_CFGSPACE_OP_WRITE) {
		pcieadm_cfgspace_write(fd, &data.pcb_u8[0], PCI_CAP_PTR_OFF);
	} else if (op == PCIEADM_CFGSPACE_OP_PRINT) {
		const pcieadm_cfgspace_print_t *print;

		if (walk.pcw_ofmt == NULL &&
		    pcieadm_cfgspace_filter(&walk, headshort)) {
			if ((flags & PCIEADM_CFGSPACE_F_SHORT) != 0) {
				pcieadm_print("Device %s -- %s (%s)\n",
				    pcip->pia_devstr, headstr, headshort);
			} else {
				pcieadm_print("Device %s -- %s\n",
				    pcip->pia_devstr, headstr);
			}
		}

		pcieadm_strfilt_push(&walk, headshort);
		pcieadm_indent();
		for (print = header; print->pcp_short != NULL; print++) {
			print->pcp_print(&walk, print, print->pcp_arg);
		}
		pcieadm_deindent();
		pcieadm_strfilt_pop(&walk);
	}


	if (!capsup) {
		return;
	}

	for (uint32_t i = PCI_CAP_PTR_OFF / 4; i < PCI_CONF_HDR_SIZE / 4; i++) {
		if (!readf(i * 4, 4, &data.pcb_u32[i], readarg)) {
			errx(EXIT_FAILURE, "failed to read offset %u from "
			    "configuration space", i * 4);
		}
	}
	walk.pcw_valid = PCIE_EXT_CAP;
	VERIFY3P(walk.pcw_filt, ==, NULL);

	if (op == PCIEADM_CFGSPACE_OP_WRITE) {
		pcieadm_cfgspace_write(fd, &data.pcb_u8[PCI_CAP_PTR_OFF],
		    PCI_CONF_HDR_SIZE - PCI_CAP_PTR_OFF);
	}

	ncaps = 0;
	cap = data.pcb_u8[PCI_CONF_CAP_PTR];
	while (cap != 0 && cap != PCI_EINVAL8) {
		const pcieadm_pci_cap_t *cap_info;
		const pcieadm_cap_vers_t *vers_info = NULL;
		const pcieadm_subcap_t *subcap = NULL;
		uint8_t cap_id, nextcap;
		uint32_t read_len = 0;

		/*
		 * The PCI specification requires that the caller mask off the
		 * bottom two bits. Always check for an invalid value (all 1s)
		 * before this.
		 */
		cap &= PCI_CAP_PTR_MASK;
		cap_id = data.pcb_u8[cap + PCI_CAP_ID];
		nextcap = data.pcb_u8[cap + PCI_CAP_NEXT_PTR];
		cap_info = pcieadm_cfgspace_match_cap(cap_id, B_FALSE);
		if (cap_info != NULL && cap_info->ppc_info != NULL) {
			cap_info->ppc_info(&walk, cap_info, cap, &vers_info,
			    &read_len, &subcap);
		}

		walk.pcw_caplen = read_len;
		walk.pcw_capoff = cap;

		if (cap_id == PCI_CAP_ID_PCI_E) {
			extcfg = B_TRUE;
			if (walk.pcw_valid != 0) {
				walk.pcw_pcietype = data.pcb_u8[cap +
				    PCIE_PCIECAP] & PCIE_PCIECAP_DEV_TYPE_MASK;
				walk.pcw_nlanes = (data.pcb_u8[cap +
				    PCIE_LINKCAP] & 0xf0) >> 4;
				walk.pcw_nlanes |= (data.pcb_u8[cap +
				    PCIE_LINKCAP + 1] & 0x01) << 4;
			} else {
				walk.pcw_pcietype = UINT_MAX;
			}
		}

		if (op == PCIEADM_CFGSPACE_OP_PRINT) {
			pcieadm_cfgspace_print_cap(&walk, cap_id, cap_info,
			    vers_info, subcap);
		}

		cap = nextcap;
		ncaps++;
		if (ncaps >= PCI_CAP_MAX_PTR) {
			errx(EXIT_FAILURE, "encountered more PCI capabilities "
			    "than fit in configuration space");
		}
	}

	if (!extcfg) {
		return;
	}

	for (uint_t i = PCIE_EXT_CAP / 4; i < PCIE_CONF_HDR_SIZE / 4; i++) {
		if (!readf(i * 4, 4, &data.pcb_u32[i], readarg)) {
			errx(EXIT_FAILURE, "failed to read offset %u from "
			    "configuration space", i * 4);
		}
	}
	walk.pcw_valid = PCIE_CONF_HDR_SIZE;

	if (op == PCIEADM_CFGSPACE_OP_WRITE) {
		pcieadm_cfgspace_write(fd, &data.pcb_u8[PCIE_EXT_CAP],
		    PCIE_CONF_HDR_SIZE - PCIE_EXT_CAP);
		return;
	}

	cap = PCIE_EXT_CAP;
	ncaps = 0;
	while (cap != 0 && cap != PCI_EINVAL16) {
		uint16_t cap_id, nextcap;
		const pcieadm_pci_cap_t *cap_info;
		const pcieadm_cap_vers_t *vers_info = NULL;
		const pcieadm_subcap_t *subcap = NULL;
		uint32_t read_len = 0;

		/*
		 * PCIe has the same masking as PCI. Note, sys/pcie.h currently
		 * has PCIE_EXT_CAP_NEXT_PTR_MASK as 0xfff, instead of the
		 * below. This should be switched to PCIE_EXT_CAP_NEXT_PTR_MASK
		 * when the kernel headers are fixed.
		 */
		cap &= 0xffc;

		/*
		 * While this seems duplicative of the loop condition, a device
		 * without capabilities indicates it with a zero for the first
		 * cap.
		 */
		if (data.pcb_u32[cap / 4] == 0 ||
		    data.pcb_u32[cap / 4] == PCI_EINVAL32)
			break;

		cap_id = data.pcb_u32[cap / 4] & PCIE_EXT_CAP_ID_MASK;
		nextcap = (data.pcb_u32[cap / 4] >>
		    PCIE_EXT_CAP_NEXT_PTR_SHIFT) & PCIE_EXT_CAP_NEXT_PTR_MASK;

		cap_info = pcieadm_cfgspace_match_cap(cap_id, B_TRUE);
		if (cap_info != NULL && cap_info->ppc_info != NULL) {
			cap_info->ppc_info(&walk, cap_info, cap, &vers_info,
			    &read_len, &subcap);
		}

		walk.pcw_caplen = read_len;
		walk.pcw_capoff = cap;

		if (op == PCIEADM_CFGSPACE_OP_PRINT) {
			pcieadm_cfgspace_print_cap(&walk, cap_id, cap_info,
			    vers_info, subcap);
		}

		cap = nextcap;
		ncaps++;
		if (ncaps >= PCIE_EXT_CAP_MAX_PTR) {
			errx(EXIT_FAILURE, "encountered more PCI capabilities "
			    "than fit in configuration space");
		}
	}
}

void
pcieadm_show_cfgspace_usage(FILE *f)
{
	(void) fprintf(f, "\tshow-cfgspace\t[-L] [-n] [-H] -d device | -f file "
	    "[filter...]\n");
	(void) fprintf(f, "\tshow-cfgspace\t-p -o field[,...] [-H] -d device | "
	    "-f file [filter...]\n");
}

static void
pcieadm_show_cfgspace_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s show-cfgspace [-L] [-n] [-H] -d "
	    "device | -f file [filter...]\n", pcieadm_progname);
	(void) fprintf(stderr, "        %s show-cfgspace -p -o field[,...] "
	    "[-H] -d device | -f file\n\t\t\t      [filter...]\n",
	    pcieadm_progname);

	(void) fprintf(stderr, "\nPrint and decode PCI configuration space "
	    "data from a device or file. Each\n<filter> selects a given "
	    "capability, sub-capability, register, or field to print.\n\n"
	    "\t-d device\tread data from the specified device (driver instance,"
	    "\n\t\t\t/devices path, or b/d/f)\n"
	    "\t-f file\t\tread data from the specified file\n"
	    "\t-L\t\tlist printable fields\n"
	    "\t-n\t\tshow printable short names\n"
	    "\t-H\t\tomit the column header (for -L and -p)\n"
	    "\t-p\t\tparsable output (requires -o)\n"
	    "\t-o field\toutput fields to print (required for -p)\n\n"
	    "The following fields are supported:\n"
	    "\thuman\t\ta human-readable description of the specific output\n"
	    "\tshort\t\tthe short name of the value used for filters\n"
	    "\tvalue\t\tthe value of a the given capability, register, etc.\n");
}

int
pcieadm_show_cfgspace(pcieadm_t *pcip, int argc, char *argv[])
{
	int c, ret;
	pcieadm_cfgspace_f readf;
	void *readarg;
	boolean_t list = B_FALSE, parse = B_FALSE;
	const char *device = NULL, *file = NULL, *fields = NULL;
	uint_t nfilts = 0;
	pcieadm_cfgspace_filter_t *filts = NULL;
	pcieadm_cfgspace_flags_t flags = 0;
	uint_t oflags = 0;
	ofmt_handle_t ofmt = NULL;

	while ((c = getopt(argc, argv, ":HLd:f:o:np")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'L':
			list = B_TRUE;
			break;
		case 'f':
			file = optarg;
			break;
		case 'p':
			parse = B_TRUE;
			flags |= PCIEADM_CFGSPACE_F_PARSE;
			oflags |= OFMT_PARSABLE;
			break;
		case 'n':
			flags |= PCIEADM_CFGSPACE_F_SHORT;
			break;
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			break;
		case ':':
			pcieadm_show_cfgspace_help("Option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
		default:
			pcieadm_show_cfgspace_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (device == NULL && file == NULL) {
		pcieadm_show_cfgspace_help("one of -d or -f must be specified");
		exit(EXIT_USAGE);
	}

	if (device != NULL && file != NULL) {
		pcieadm_show_cfgspace_help("only one of -d and -f must be "
		    "specified");
		exit(EXIT_USAGE);
	}

	if (parse && fields == NULL) {
		pcieadm_show_cfgspace_help("-p requires fields specified with "
		    "-o");
		exit(EXIT_USAGE);
	}

	if (!parse && fields != NULL) {
		pcieadm_show_cfgspace_help("-o can only be used with -p");
		exit(EXIT_USAGE);
	}

	if ((oflags & OFMT_NOHEADER) && !(list || parse)) {
		pcieadm_show_cfgspace_help("-H must be used with either -L or "
		    "-p");
		exit(EXIT_USAGE);
	}

	if ((flags & PCIEADM_CFGSPACE_F_SHORT) && (list || parse)) {
		pcieadm_show_cfgspace_help("-n cannot be used with either -L "
		    "or -p");
		exit(EXIT_USAGE);
	}

	if (list && parse != 0) {
		pcieadm_show_cfgspace_help("-L and -p cannot be used together");
		exit(EXIT_USAGE);
	}

	if (list && fields != NULL) {
		pcieadm_show_cfgspace_help("-L and -o cannot be used together");
		exit(EXIT_USAGE);
	}

	if (list) {
		fields = "short,human";
	}

	if (argc > 0) {
		nfilts = argc;
		filts = calloc(nfilts, sizeof (pcieadm_cfgspace_filter_t));

		for (int i = 0; i < argc; i++) {
			filts[i].pcf_string = argv[i];
			filts[i].pcf_len = strlen(argv[i]);
		}
	}

	if (list || parse) {
		ofmt_status_t oferr;
		oferr = ofmt_open(fields, pcieadm_cfgspace_ofmt, oflags, 0,
		    &ofmt);
		ofmt_check(oferr, parse, ofmt, pcieadm_ofmt_errx, warnx);
	}

	/*
	 * Initialize privileges that we require. For reading from the kernel
	 * we require all privileges. For a file, we just intersect with things
	 * that would allow someone to read from any file.
	 */
	if (device != NULL) {
		/*
		 * We need full privileges if reading from a device,
		 * unfortunately.
		 */
		priv_fillset(pcip->pia_priv_eff);
	} else {
		VERIFY0(priv_addset(pcip->pia_priv_eff, PRIV_FILE_DAC_READ));
		VERIFY0(priv_addset(pcip->pia_priv_eff, PRIV_FILE_DAC_SEARCH));
	}
	pcieadm_init_privs(pcip);

	if (device != NULL) {
		pcieadm_find_dip(pcip, device);
		pcieadm_init_cfgspace_kernel(pcip, &readf, &readarg);
	} else {
		pcip->pia_devstr = file;
		pcieadm_init_cfgspace_file(pcip, file, &readf, &readarg);
	}
	pcieadm_cfgspace(pcip, PCIEADM_CFGSPACE_OP_PRINT, readf, -1, readarg,
	    nfilts, filts, flags, ofmt);
	if (device != NULL) {
		pcieadm_fini_cfgspace_kernel(readarg);
	} else {
		pcieadm_fini_cfgspace_file(readarg);
	}

	ofmt_close(ofmt);
	ret = EXIT_SUCCESS;
	for (uint_t i = 0; i < nfilts; i++) {
		if (!filts[i].pcf_used) {
			warnx("filter '%s' did not match any fields",
			    filts[i].pcf_string);
			ret = EXIT_FAILURE;
		}
	}

	return (ret);
}

typedef struct pcieadm_save_cfgspace {
	pcieadm_t *psc_pci;
	int psc_dirfd;
	uint_t psc_nsaved;
	int psc_ret;
} pcieadm_save_cfgspace_t;

static int
pcieadm_save_cfgspace_cb(di_node_t devi, void *arg)
{
	int fd, nregs, *regs;
	pcieadm_save_cfgspace_t *psc = arg;
	pcieadm_cfgspace_f readf;
	void *readarg;
	char fname[128];

	psc->psc_pci->pia_devstr = di_node_name(devi);
	psc->psc_pci->pia_devi = devi;
	psc->psc_pci->pia_nexus = DI_NODE_NIL;
	pcieadm_find_nexus(psc->psc_pci);
	if (psc->psc_pci->pia_nexus == DI_NODE_NIL) {
		warnx("failed to find nexus for %s", di_node_name(devi));
		psc->psc_ret = EXIT_FAILURE;
		return (DI_WALK_CONTINUE);
	}

	nregs = di_prop_lookup_ints(DDI_DEV_T_ANY, devi, "reg", &regs);
	if (nregs <= 0) {
		warnx("failed to lookup regs array for %s",
		    psc->psc_pci->pia_devstr);
		psc->psc_ret = EXIT_FAILURE;
		return (DI_WALK_CONTINUE);
	}

	(void) snprintf(fname, sizeof (fname), "%02x-%02x-%02x.pci",
	    PCI_REG_BUS_G(regs[0]), PCI_REG_DEV_G(regs[0]),
	    PCI_REG_FUNC_G(regs[0]));

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, psc->psc_pci->pia_priv_eff) !=
	    0) {
		err(EXIT_FAILURE, "failed to raise privileges");
	}
	fd = openat(psc->psc_dirfd, fname, O_WRONLY | O_TRUNC | O_CREAT, 0666);
	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, psc->psc_pci->pia_priv_min) !=
	    0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	if (fd < 0) {
		warn("failed to create output file %s", fname);
		psc->psc_ret = EXIT_FAILURE;
		return (DI_WALK_CONTINUE);
	}

	pcieadm_init_cfgspace_kernel(psc->psc_pci, &readf, &readarg);
	pcieadm_cfgspace(psc->psc_pci, PCIEADM_CFGSPACE_OP_WRITE, readf, fd,
	    readarg, 0, NULL, 0, NULL);
	pcieadm_fini_cfgspace_kernel(readarg);

	if (close(fd) != 0) {
		warn("failed to close output fd for %s", fname);
		psc->psc_ret = EXIT_FAILURE;
	} else {
		psc->psc_nsaved++;
	}

	return (DI_WALK_CONTINUE);
}

void
pcieadm_save_cfgspace_usage(FILE *f)
{
	(void) fprintf(f, "\tsave-cfgspace\t-d device output-file\n");
	(void) fprintf(f, "\tsave-cfgspace\t-a output-directory\n");
}

static void
pcieadm_save_cfgspace_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s save-cfgspace -d device "
	    "output-file\n", pcieadm_progname);
	(void) fprintf(stderr, "        %s save-cfgspace -a "
	    "output-directory\n", pcieadm_progname);

	(void) fprintf(stderr, "\nSave PCI configuration space data from a "
	    "device to a file or\nsave all devices to a specified directory."
	    "\n\n"
	    "\t-a\t\tsave data from all devices\n"
	    "\t-d device\tread data from the specified device (driver instance,"
	    "\n\t\t\t/devices path, or b/d/f)\n");
}

int
pcieadm_save_cfgspace(pcieadm_t *pcip, int argc, char *argv[])
{
	int c;
	pcieadm_cfgspace_f readf;
	void *readarg;
	const char *device = NULL;
	boolean_t do_all = B_FALSE;

	while ((c = getopt(argc, argv, ":ad:")) != -1) {
		switch (c) {
		case 'a':
			do_all = B_TRUE;
			break;
		case 'd':
			device = optarg;
			break;
		case ':':
			pcieadm_save_cfgspace_help("Option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
		default:
			pcieadm_save_cfgspace_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (device == NULL && !do_all) {
		pcieadm_save_cfgspace_help("missing required -d option to "
		    "indicate device to dump");
		exit(EXIT_USAGE);
	}

	if (argc != 1) {
		pcieadm_save_cfgspace_help("missing required output path");
		exit(EXIT_USAGE);
	}

	/*
	 * For reading from devices, we need to full privileges, unfortunately.
	 */
	priv_fillset(pcip->pia_priv_eff);
	pcieadm_init_privs(pcip);

	if (!do_all) {
		int fd;

		pcieadm_find_dip(pcip, device);

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) !=
		    0) {
			err(EXIT_FAILURE, "failed to raise privileges");
		}

		if ((fd = open(argv[0], O_WRONLY | O_CREAT | O_TRUNC, 0666)) <
		    0) {
			err(EXIT_FAILURE, "failed to open output file %s",
			    argv[0]);
		}

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) !=
		    0) {
			err(EXIT_FAILURE, "failed to reduce privileges");
		}

		pcieadm_init_cfgspace_kernel(pcip, &readf, &readarg);
		pcieadm_cfgspace(pcip, PCIEADM_CFGSPACE_OP_WRITE, readf, fd,
		    readarg, 0, NULL, 0, NULL);
		pcieadm_fini_cfgspace_kernel(readarg);

		if (close(fd) != 0) {
			err(EXIT_FAILURE, "failed to close output file "
			    "descriptor");
		}

		return (EXIT_SUCCESS);
	} else {
		pcieadm_save_cfgspace_t psc;
		pcieadm_di_walk_t walk;

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) !=
		    0) {
			err(EXIT_FAILURE, "failed to raise privileges");
		}

		if ((psc.psc_dirfd = open(argv[0], O_RDONLY | O_DIRECTORY)) <
		    0) {
			err(EXIT_FAILURE, "failed to open output directory %s",
			    argv[0]);
		}

		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) !=
		    0) {
			err(EXIT_FAILURE, "failed to reduce privileges");
		}

		psc.psc_nsaved = 0;
		psc.psc_ret = EXIT_SUCCESS;
		psc.psc_pci = pcip;

		walk.pdw_arg = &psc;
		walk.pdw_func = pcieadm_save_cfgspace_cb;
		pcieadm_di_walk(pcip, &walk);

		VERIFY0(close(psc.psc_dirfd));

		if (psc.psc_nsaved == 0) {
			warnx("failed to save any PCI devices");
			return (EXIT_FAILURE);
		}

		pcieadm_print("successfully saved %u devices to %s\n",
		    psc.psc_nsaved, argv[0]);
		return (psc.psc_ret);
	}
}
