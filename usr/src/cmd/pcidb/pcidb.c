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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * A tool to interface with the pci.ids database driven by libpcidb.
 */

#include <stdio.h>
#include <stdarg.h>
#include <pcidb.h>
#include <err.h>
#include <libgen.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ofmt.h>
#include <errno.h>
#include <sys/debug.h>
#include <priv.h>

#define	EXIT_USAGE	2

static char *pcidb_progname;

typedef enum {
	PCIDB_MODE_UNKNOWN,
	PCIDB_MODE_LIST,
	PCIDB_MODE_SEARCH,
	PCIDB_MODE_LOOKUP
} pcidb_mode_t;

typedef enum {
	PCIDB_TABLE_NONE,
	PCIDB_TABLE_VENDOR,
	PCIDB_TABLE_DEVICE,
	PCIDB_TABLE_SUBSYSTEM,
	PCIDB_TABLE_CLASS,
	PCIDB_TABLE_SUBCLASS,
	PCIDB_TABLE_PROGIF
} pcidb_table_t;

typedef enum {
	PCIDB_OFMT_VID,
	PCIDB_OFMT_VENSTR,
	PCIDB_OFMT_DID,
	PCIDB_OFMT_DEVSTR,
	PCIDB_OFMT_SVID,
	PCIDB_OFMT_SDID,
	PCIDB_OFMT_SUBVENSTR,
	PCIDB_OFMT_SUBSYSSTR,
	PCIDB_OFMT_BCC,
	PCIDB_OFMT_CLASSSTR,
	PCIDB_OFMT_SCC,
	PCIDB_OFMT_SUBCLASSSTR,
	PCIDB_OFMT_PI,
	PCIDB_OFMT_PROGIFSTR
} pcidb_ofmt_t;

typedef struct pcidb_filter {
	uint32_t pft_vend;
	uint32_t pft_dev;
	uint32_t pft_subven;
	uint32_t pft_subdev;
	uint32_t pft_class;
	uint32_t pft_subclass;
	uint32_t pft_progif;
} pcidb_filter_t;

#define	PCIDB_NOFILTER	UINT32_MAX

typedef struct pcidb_walk {
	pcidb_hdl_t *pw_hdl;
	ofmt_handle_t pw_ofmt;
	pcidb_vendor_t *pw_vendor;
	pcidb_device_t *pw_device;
	pcidb_subvd_t *pw_subvd;
	pcidb_class_t *pw_class;
	pcidb_subclass_t *pw_subclass;
	pcidb_progif_t *pw_progif;
	boolean_t pw_strcase;
	uint_t pw_nfilters;
	pcidb_filter_t *pw_filters;
} pcidb_walk_t;

static boolean_t
pcidb_write_vendor(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	pcidb_walk_t *walk = ofarg->ofmt_cbarg;

	VERIFY(walk->pw_vendor != NULL);
	switch (ofarg->ofmt_id) {
	case PCIDB_OFMT_VID:
		(void) snprintf(buf, buflen, "%x",
		    pcidb_vendor_id(walk->pw_vendor));
		break;
	case PCIDB_OFMT_VENSTR:
		(void) strlcpy(buf, pcidb_vendor_name(walk->pw_vendor), buflen);
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static boolean_t
pcidb_write_device(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	pcidb_walk_t *walk = ofarg->ofmt_cbarg;

	VERIFY(walk->pw_device != NULL);
	switch (ofarg->ofmt_id) {
	case PCIDB_OFMT_DID:
		(void) snprintf(buf, buflen, "%x",
		    pcidb_device_id(walk->pw_device));
		break;
	case PCIDB_OFMT_DEVSTR:
		(void) strlcpy(buf, pcidb_device_name(walk->pw_device), buflen);
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static boolean_t
pcidb_write_subsystem(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	pcidb_walk_t *walk = ofarg->ofmt_cbarg;
	pcidb_vendor_t *vendor;

	VERIFY(walk->pw_subvd != NULL);
	switch (ofarg->ofmt_id) {
	case PCIDB_OFMT_SVID:
		(void) snprintf(buf, buflen, "%x",
		    pcidb_subvd_svid(walk->pw_subvd));
		break;
	case PCIDB_OFMT_SDID:
		(void) snprintf(buf, buflen, "%x",
		    pcidb_subvd_sdid(walk->pw_subvd));
		break;
	case PCIDB_OFMT_SUBSYSSTR:
		(void) strlcpy(buf, pcidb_subvd_name(walk->pw_subvd), buflen);
		break;
	case PCIDB_OFMT_SUBVENSTR:
		vendor = pcidb_lookup_vendor(walk->pw_hdl,
		    pcidb_subvd_svid(walk->pw_subvd));
		if (vendor == NULL) {
			return (B_FALSE);
		}
		(void) strlcpy(buf, pcidb_vendor_name(vendor), buflen);
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static boolean_t
pcidb_write_class(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	pcidb_walk_t *walk = ofarg->ofmt_cbarg;

	VERIFY(walk->pw_class != NULL);
	switch (ofarg->ofmt_id) {
	case PCIDB_OFMT_BCC:
		(void) snprintf(buf, buflen, "%x",
		    pcidb_class_code(walk->pw_class));
		break;
	case PCIDB_OFMT_CLASSSTR:
		(void) strlcpy(buf, pcidb_class_name(walk->pw_class), buflen);
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static boolean_t
pcidb_write_subclass(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	pcidb_walk_t *walk = ofarg->ofmt_cbarg;

	VERIFY(walk->pw_subclass != NULL);
	switch (ofarg->ofmt_id) {
	case PCIDB_OFMT_SCC:
		(void) snprintf(buf, buflen, "%x",
		    pcidb_subclass_code(walk->pw_subclass));
		break;
	case PCIDB_OFMT_SUBCLASSSTR:
		(void) strlcpy(buf, pcidb_subclass_name(walk->pw_subclass),
		    buflen);
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static boolean_t
pcidb_write_progif(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	pcidb_walk_t *walk = ofarg->ofmt_cbarg;

	VERIFY(walk->pw_progif != NULL);
	switch (ofarg->ofmt_id) {
	case PCIDB_OFMT_PI:
		(void) snprintf(buf, buflen, "%x",
		    pcidb_progif_code(walk->pw_progif));
		break;
	case PCIDB_OFMT_PROGIFSTR:
		(void) strlcpy(buf, pcidb_progif_name(walk->pw_progif),
		    buflen);
		break;
	default:
		abort();
	}
	return (B_TRUE);
}

static const char *pcidb_vendor_fields = "vid,vendor";
static const ofmt_field_t pcidb_vendor_ofmt[] = {
	{ "VID",	8,	PCIDB_OFMT_VID,		pcidb_write_vendor },
	{ "VENDOR",	30,	PCIDB_OFMT_VENSTR,	pcidb_write_vendor },
	{ NULL, 0, 0, NULL }
};

static const char *pcidb_device_fields = "vid,did,vendor,device";
static const ofmt_field_t pcidb_device_ofmt[] = {
	{ "VID",	8,	PCIDB_OFMT_VID,		pcidb_write_vendor },
	{ "VENDOR",	30,	PCIDB_OFMT_VENSTR,	pcidb_write_vendor },
	{ "DID",	8,	PCIDB_OFMT_DID,		pcidb_write_device },
	{ "DEVICE",	30,	PCIDB_OFMT_DEVSTR,	pcidb_write_device },
	{ NULL, 0, 0, NULL }
};

static const char *pcidb_subsystem_fields = "vid,did,svid,sdid,subsystem";
static const ofmt_field_t pcidb_subsystem_ofmt[] = {
	{ "VID",	8,	PCIDB_OFMT_VID,		pcidb_write_vendor },
	{ "VENDOR",	30,	PCIDB_OFMT_VENSTR,	pcidb_write_vendor },
	{ "DID",	8,	PCIDB_OFMT_DID,		pcidb_write_device },
	{ "DEVICE",	30,	PCIDB_OFMT_DEVSTR,	pcidb_write_device },
	{ "SVID",	8,	PCIDB_OFMT_SVID,	pcidb_write_subsystem },
	{ "SDID",	8,	PCIDB_OFMT_SDID,	pcidb_write_subsystem },
	{ "SUBSYSTEM",	30,	PCIDB_OFMT_SUBSYSSTR,	pcidb_write_subsystem },
	{ "SUBVENDOR",	30,	PCIDB_OFMT_SUBVENSTR,	pcidb_write_subsystem },
	{ NULL, 0, 0, NULL }
};

static const char *pcidb_class_fields = "bcc,class";
static const ofmt_field_t pcidb_class_ofmt[] = {
	{ "BCC",	6,	PCIDB_OFMT_BCC,		pcidb_write_class },
	{ "CLASS",	30,	PCIDB_OFMT_CLASSSTR,	pcidb_write_class },
	{ NULL, 0, 0, NULL }
};

static const char *pcidb_subclass_fields = "bcc,scc,class,subclass";
static const ofmt_field_t pcidb_subclass_ofmt[] = {
	{ "BCC",	6,	PCIDB_OFMT_BCC,		pcidb_write_class },
	{ "CLASS",	30,	PCIDB_OFMT_CLASSSTR,	pcidb_write_class },
	{ "SCC",	6,	PCIDB_OFMT_SCC,		pcidb_write_subclass },
	{ "SUBCLASS",	30,	PCIDB_OFMT_SUBCLASSSTR,	pcidb_write_subclass },
	{ NULL, 0, 0, NULL }
};

static const char *pcidb_progif_fields = "bcc,scc,pi,subclass,interface";
static const ofmt_field_t pcidb_progif_ofmt[] = {
	{ "BCC",	6,	PCIDB_OFMT_BCC,		pcidb_write_class },
	{ "CLASS",	30,	PCIDB_OFMT_CLASSSTR,	pcidb_write_class },
	{ "SCC",	6,	PCIDB_OFMT_SCC,		pcidb_write_subclass },
	{ "SUBCLASS",	30,	PCIDB_OFMT_SUBCLASSSTR,	pcidb_write_subclass },
	{ "PI",		6,	PCIDB_OFMT_PI,		pcidb_write_progif },
	{ "INTERFACE",	30,	PCIDB_OFMT_PROGIFSTR,	pcidb_write_progif },
	{ NULL, 0, 0, NULL }
};

static void
pcidb_ofmt_errx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
}

static boolean_t
pcidb_filter_match(pcidb_walk_t *walk)
{
	if (walk->pw_nfilters == 0) {
		return (B_TRUE);
	}

	for (uint_t i = 0; i < walk->pw_nfilters; i++) {
		const pcidb_filter_t *filt = &walk->pw_filters[i];
		if (filt->pft_vend != PCIDB_NOFILTER &&
		    (walk->pw_vendor == NULL ||
		    filt->pft_vend != pcidb_vendor_id(walk->pw_vendor))) {
			continue;
		}

		if (filt->pft_dev != PCIDB_NOFILTER &&
		    (walk->pw_device == NULL ||
		    filt->pft_dev != pcidb_device_id(walk->pw_device))) {
			continue;
		}

		if (filt->pft_subven != PCIDB_NOFILTER &&
		    (walk->pw_subvd == NULL ||
		    filt->pft_subven != pcidb_subvd_svid(walk->pw_subvd))) {
			continue;
		}

		if (filt->pft_subdev != PCIDB_NOFILTER &&
		    (walk->pw_subvd == NULL ||
		    filt->pft_subdev != pcidb_subvd_sdid(walk->pw_subvd))) {
			continue;
		}

		if (filt->pft_class != PCIDB_NOFILTER &&
		    (walk->pw_class == NULL ||
		    filt->pft_class != pcidb_class_code(walk->pw_class))) {
			continue;
		}

		if (filt->pft_subclass != PCIDB_NOFILTER &&
		    (walk->pw_subclass == NULL ||
		    filt->pft_subclass !=
		    pcidb_subclass_code(walk->pw_subclass))) {
			continue;
		}

		if (filt->pft_progif != PCIDB_NOFILTER &&
		    (walk->pw_progif == NULL ||
		    filt->pft_progif != pcidb_progif_code(walk->pw_progif))) {
			continue;
		}

		return (B_TRUE);
	}

	return (B_FALSE);
}

static void
pcidb_walk_vendors(pcidb_walk_t *walk)
{
	pcidb_hdl_t *hdl = walk->pw_hdl;

	for (pcidb_vendor_t *vend = pcidb_vendor_iter(hdl); vend != NULL;
	    vend = pcidb_vendor_iter_next(vend)) {
		walk->pw_vendor = vend;
		if (!pcidb_filter_match(walk))
			continue;
		ofmt_print(walk->pw_ofmt, walk);
	}
}

static void
pcidb_walk_devices(pcidb_walk_t *walk)
{
	pcidb_hdl_t *hdl = walk->pw_hdl;

	for (pcidb_vendor_t *vend = pcidb_vendor_iter(hdl); vend != NULL;
	    vend = pcidb_vendor_iter_next(vend)) {
		walk->pw_vendor = vend;
		for (pcidb_device_t *dev = pcidb_device_iter(vend); dev != NULL;
		    dev = pcidb_device_iter_next(dev)) {
			walk->pw_device = dev;
			if (!pcidb_filter_match(walk))
				continue;
			ofmt_print(walk->pw_ofmt, walk);
		}
	}
}

static void
pcidb_walk_subsystems(pcidb_walk_t *walk)
{
	pcidb_hdl_t *hdl = walk->pw_hdl;

	for (pcidb_vendor_t *vend = pcidb_vendor_iter(hdl); vend != NULL;
	    vend = pcidb_vendor_iter_next(vend)) {
		walk->pw_vendor = vend;
		for (pcidb_device_t *dev = pcidb_device_iter(vend); dev != NULL;
		    dev = pcidb_device_iter_next(dev)) {
			walk->pw_device = dev;
			for (pcidb_subvd_t *sub = pcidb_subvd_iter(dev);
			    sub != NULL; sub = pcidb_subvd_iter_next(sub)) {
				walk->pw_subvd = sub;
				if (!pcidb_filter_match(walk))
					continue;
				ofmt_print(walk->pw_ofmt, walk);
			}
		}

	}
}

static void
pcidb_walk_classes(pcidb_walk_t *walk)
{
	for (pcidb_class_t *class = pcidb_class_iter(walk->pw_hdl);
	    class != NULL; class = pcidb_class_iter_next(class)) {
		walk->pw_class = class;
		if (!pcidb_filter_match(walk))
			continue;
		ofmt_print(walk->pw_ofmt, walk);
	}
}

static void
pcidb_walk_subclasses(pcidb_walk_t *walk)
{
	for (pcidb_class_t *class = pcidb_class_iter(walk->pw_hdl);
	    class != NULL; class = pcidb_class_iter_next(class)) {
		walk->pw_class = class;
		for (pcidb_subclass_t *sub = pcidb_subclass_iter(class);
		    sub != NULL; sub = pcidb_subclass_iter_next(sub)) {
			walk->pw_subclass = sub;
			if (!pcidb_filter_match(walk))
				continue;
			ofmt_print(walk->pw_ofmt, walk);
		}
	}
}

static void
pcidb_walk_progifs(pcidb_walk_t *walk)
{
	for (pcidb_class_t *class = pcidb_class_iter(walk->pw_hdl);
	    class != NULL; class = pcidb_class_iter_next(class)) {
		walk->pw_class = class;
		for (pcidb_subclass_t *sub = pcidb_subclass_iter(class);
		    sub != NULL; sub = pcidb_subclass_iter_next(sub)) {
			walk->pw_subclass = sub;
			for (pcidb_progif_t *progif = pcidb_progif_iter(sub);
			    progif != NULL;
			    progif = pcidb_progif_iter_next(progif)) {
				walk->pw_progif = progif;
				if (!pcidb_filter_match(walk))
					continue;
				ofmt_print(walk->pw_ofmt, walk);
			}
		}
	}
}

static void
pcidb_parse_class_filter(pcidb_filter_t *filter, char *arg, const char *orig)
{
	size_t len;
	unsigned long val;
	char *eptr;

	filter->pft_vend = filter->pft_dev = PCIDB_NOFILTER;
	filter->pft_subven = filter->pft_subdev = PCIDB_NOFILTER;

	len = strlen(arg);
	if (len != 2 && len != 4 && len != 6) {
		errx(EXIT_FAILURE, "invalid class filter: '%s': bad length",
		    orig);
	}

	errno = 0;
	val = strtoul(arg, &eptr, 16);
	if (errno != 0 || *eptr != '\0') {
		errx(EXIT_FAILURE, "invalid class filter: '%s': failed to "
		    "parse hex string", orig);
	}

	if (len == 6) {
		filter->pft_progif = val & 0xff;
		val = val >> 8;
	} else {
		filter->pft_progif = PCIDB_NOFILTER;
	}

	if (len >= 4) {
		filter->pft_subclass = val & 0xff;
		val = val >> 8;
	} else {
		filter->pft_subclass = PCIDB_NOFILTER;
	}

	filter->pft_class = val & 0xff;
}

static void
pcidb_parse_device_filter(pcidb_filter_t *filter, char *arg, const char *orig)
{
	unsigned long val;
	uint32_t primary, secondary;
	char *eptr;

	filter->pft_vend = filter->pft_dev = PCIDB_NOFILTER;
	filter->pft_subven = filter->pft_subdev = PCIDB_NOFILTER;
	filter->pft_class = filter->pft_subclass = PCIDB_NOFILTER;
	filter->pft_progif = PCIDB_NOFILTER;

	errno = 0;
	val = strtoul(arg, &eptr, 16);
	if (errno != 0 || (*eptr != '\0' && *eptr != ',')) {
		errx(EXIT_FAILURE, "invalid device filter: '%s': failed to "
		    "parse hex string", orig);
	}

	if (val > UINT16_MAX) {
		errx(EXIT_FAILURE, "invalid id: %lx is larger than 0xffff",
		    val);
	}

	primary = (uint32_t)val;
	if (*eptr == '\0') {
		filter->pft_vend = primary;
		return;
	} else if (strcmp(eptr, ",s") == 0) {
		filter->pft_subven = primary;
		return;
	} else if (eptr[1] == '\0') {
		errx(EXIT_FAILURE, "invalid device filter: '%s': filter "
		    "terminated early", arg);
	}

	arg = eptr + 1;
	val = strtoul(arg, &eptr, 16);
	if (errno != 0 || (*eptr != '\0' && *eptr != ',' && *eptr != '.')) {
		errx(EXIT_FAILURE, "invalid device filter: '%s': failed to "
		    "parse hex string at %s", orig, arg);
	}

	if (val > UINT16_MAX) {
		errx(EXIT_FAILURE, "invalid id: %lx is larger than 0xffff",
		    val);
	}

	secondary = (uint32_t)val;
	if (*eptr == '\0') {
		filter->pft_vend = primary;
		filter->pft_dev = secondary;
		return;
	} else if (eptr[1] == '\0') {
		errx(EXIT_FAILURE, "invalid device filter: '%s': filter "
		    "terminated early", arg);
	}

	if (*eptr == ',') {
		if (eptr[1] == 'p' && eptr[2] == '\0') {
			filter->pft_vend = primary;
			filter->pft_dev = secondary;
			return;
		}
		if (eptr[1] == 's' && eptr[2] == '\0') {
			filter->pft_subven = primary;
			filter->pft_subdev = secondary;
			return;
		}
		errx(EXIT_FAILURE, "invalid device filter: '%s': invalid "
		    "trailing comma at %s, expected either ,p or ,s",
		    orig, eptr);
	}

	filter->pft_vend = primary;
	filter->pft_dev = secondary;

	arg = eptr + 1;
	errno = 0;
	val = strtoul(arg, &eptr, 16);
	if (errno != 0 || (*eptr != '\0' && *eptr != ',')) {
		errx(EXIT_FAILURE, "invalid device filter: '%s': failed to "
		    "parse hex string at %s", orig, arg);
	}

	if (val > UINT16_MAX) {
		errx(EXIT_FAILURE, "invalid id: %lx is larger than 0xffff",
		    val);
	}

	filter->pft_subven = (uint32_t)val;
	if (*eptr == '\0') {
		return;
	} else if (eptr[1] == '\0') {
		errx(EXIT_FAILURE, "invalid device filter: '%s': filter "
		    "terminated early", arg);
	}

	arg = eptr + 1;
	errno = 0;
	val = strtoul(arg, &eptr, 16);
	if (errno != 0 || *eptr != '\0') {
		errx(EXIT_FAILURE, "invalid device filter: '%s': failed to "
		    "parse hex string at %s", orig, arg);
	}

	if (val > UINT16_MAX) {
		errx(EXIT_FAILURE, "invalid id: %lx is larger than 0xffff",
		    val);
	}

	filter->pft_subdev = (uint32_t)val;
}


/*
 * Process a series of alias style ways of indicating numeric filters. Use the
 * basic alias format for now.
 */
static void
pcidb_process_filters(int argc, char *argv[], pcidb_walk_t *walkp)
{
	if (argc <= 0) {
		walkp->pw_nfilters = 0;
		return;
	}

	walkp->pw_nfilters = argc;
	walkp->pw_filters = calloc(walkp->pw_nfilters, sizeof (pcidb_filter_t));
	if (walkp->pw_filters == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for filters");
	}

	for (int i = 0; i < argc; i++) {
		char *str = strdup(argv[i]);

		if (str == NULL) {
			errx(EXIT_FAILURE, "failed to duplicate string %s",
			    argv[i]);
		}

		if (strncmp(str, "pciexclass,", 11) == 0) {
			pcidb_parse_class_filter(&walkp->pw_filters[i],
			    str + 11, argv[i]);
		} else if (strncmp(str, "pciclass,", 9) == 0) {
			pcidb_parse_class_filter(&walkp->pw_filters[i], str + 9,
			    argv[i]);
		} else if (strncmp(str, "pciex", 5) == 0) {
			pcidb_parse_device_filter(&walkp->pw_filters[i],
			    str + 5, argv[i]);
		} else if (strncmp(str, "pci", 3) == 0) {
			pcidb_parse_device_filter(&walkp->pw_filters[i],
			    str + 3, argv[i]);
		} else {
			errx(EXIT_FAILURE, "invalid filter string: %s", str);
		}

		free(str);
	}
}

static void
pcidb_drop_privs(void)
{
	priv_set_t *curprivs, *targprivs;

	if ((curprivs = priv_allocset()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate privilege set to drop "
		    "privs");
	}

	if (getppriv(PRIV_EFFECTIVE, curprivs) != 0) {
		err(EXIT_FAILURE, "failed to get current privileges");
	}

	if ((targprivs = priv_allocset()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate privilege set to drop "
		    "privs");
	}

	/*
	 * Set our privileges to the minimum required. Because stdout will have
	 * already been opened, all we need is the ability to read files from
	 * basic privileges. We opt to keep FILE_DAC_READ if the caller has it
	 * just in case there is something weird about the location of the
	 * pci.ids files.
	 */
	priv_basicset(targprivs);
	VERIFY0(priv_delset(targprivs, PRIV_FILE_LINK_ANY));
	VERIFY0(priv_delset(targprivs, PRIV_PROC_INFO));
	VERIFY0(priv_delset(targprivs, PRIV_PROC_SESSION));
	VERIFY0(priv_delset(targprivs, PRIV_PROC_FORK));
	VERIFY0(priv_delset(targprivs, PRIV_NET_ACCESS));
	VERIFY0(priv_delset(targprivs, PRIV_FILE_WRITE));
	VERIFY0(priv_delset(targprivs, PRIV_PROC_EXEC));
	VERIFY0(priv_addset(targprivs, PRIV_FILE_DAC_READ));

	priv_intersect(curprivs, targprivs);

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, targprivs) != 0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	priv_freeset(curprivs);
	priv_freeset(targprivs);
}

static int
pcidb_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", pcidb_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "usage:  %s [-v|-d|-s|-c|-S|-i] [-H]"
	    "[[-p] [-o <field>[,...]] [<filter>]\n\n"
	    "\t-v\t\tshow vendor table\n"
	    "\t-d\t\tshow device table\n"
	    "\t-s\t\tshow subsystem table\n"
	    "\t-c\t\tshow class table\n"
	    "\t-S\t\tshow subclass table\n"
	    "\t-i\t\tshow programming interface table\n"
	    "\t-H\t\tdo not output column headers\n"
	    "\t-p\t\toutput in parsable form\n"
	    "\t-o field\toutput only specified fields\n\n"
	    "filters take the form of PCI aliases, e.g. pci8086,1522, "
	    "pci1028,1f44,s, or\n"
	    "pciex1022,1480.1462,7c37. Classes can be specified in a similar "
	    "way, e.g.\npciclass,010802 or pciclass,0403.\n", pcidb_progname);

	return (EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	pcidb_hdl_t *hdl;
	int c;
	uint_t tablecnt = 0;
	pcidb_table_t table = PCIDB_TABLE_NONE;
	boolean_t parse = B_FALSE, strcase = B_FALSE;
	const char *fields = NULL;
	const char *ofmt_fields_str = NULL;
	const ofmt_field_t *ofmt_fields = NULL;
	ofmt_handle_t ofmt;
	ofmt_status_t oferr;
	uint_t flags = 0;
	pcidb_walk_t walk;

	bzero(&walk, sizeof (walk));
	pcidb_progname = basename(argv[0]);

	pcidb_drop_privs();

	while ((c = getopt(argc, argv, ":vdscSipo:hH")) != -1) {
		switch (c) {
		case 'v':
			tablecnt++;
			table = PCIDB_TABLE_VENDOR;
			break;
		case 'd':
			tablecnt++;
			table = PCIDB_TABLE_DEVICE;
			break;
		case 's':
			tablecnt++;
			table = PCIDB_TABLE_SUBSYSTEM;
			break;
		case 'c':
			tablecnt++;
			table = PCIDB_TABLE_CLASS;
			break;
		case 'S':
			tablecnt++;
			table = PCIDB_TABLE_SUBCLASS;
			break;
		case 'i':
			tablecnt++;
			table = PCIDB_TABLE_PROGIF;
			break;
		case 'p':
			parse = B_TRUE;
			flags |= OFMT_PARSABLE;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'h':
			return (pcidb_usage(NULL));
		case 'H':
			flags |= OFMT_NOHEADER;
			break;
		case ':':
			return (pcidb_usage("Option -%c requires an argument",
			    optopt));
		case '?':
			return (pcidb_usage("unknown option: -%c", optopt));
		}
	}

	if (tablecnt > 1) {
		errx(EXIT_USAGE, "more than one table specified, only one of "
		    "-v, -d, -s, -c, -S, and -i may be specified");
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	argc -= optind;
	argv += optind;

	pcidb_process_filters(argc, argv, &walk);

	switch (table) {
	case PCIDB_TABLE_VENDOR:
		ofmt_fields = pcidb_vendor_ofmt;
		ofmt_fields_str = pcidb_vendor_fields;
		break;
	case PCIDB_TABLE_NONE:
	case PCIDB_TABLE_DEVICE:
		ofmt_fields = pcidb_device_ofmt;
		ofmt_fields_str = pcidb_device_fields;
		break;
	case PCIDB_TABLE_SUBSYSTEM:
		ofmt_fields = pcidb_subsystem_ofmt;
		ofmt_fields_str = pcidb_subsystem_fields;
		break;
	case PCIDB_TABLE_CLASS:
		ofmt_fields = pcidb_class_ofmt;
		ofmt_fields_str = pcidb_class_fields;
		break;
	case PCIDB_TABLE_SUBCLASS:
		ofmt_fields = pcidb_subclass_ofmt;
		ofmt_fields_str = pcidb_subclass_fields;
		break;
	case PCIDB_TABLE_PROGIF:
		ofmt_fields = pcidb_progif_ofmt;
		ofmt_fields_str = pcidb_progif_fields;
		break;
	}

	if (fields == NULL) {
		fields = ofmt_fields_str;
	}

	oferr = ofmt_open(fields, ofmt_fields, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, pcidb_ofmt_errx, warnx);

	hdl = pcidb_open(PCIDB_VERSION);
	if (hdl == NULL) {
		err(EXIT_FAILURE, "failed to initialize PCI IDs database");
	}

	walk.pw_hdl = hdl;
	walk.pw_ofmt = ofmt;
	walk.pw_strcase = strcase;

	switch (table) {
	case PCIDB_TABLE_VENDOR:
		pcidb_walk_vendors(&walk);
		break;
	case PCIDB_TABLE_NONE:
	case PCIDB_TABLE_DEVICE:
		pcidb_walk_devices(&walk);
		break;
	case PCIDB_TABLE_SUBSYSTEM:
		pcidb_walk_subsystems(&walk);
		break;
	case PCIDB_TABLE_CLASS:
		pcidb_walk_classes(&walk);
		break;
	case PCIDB_TABLE_SUBCLASS:
		pcidb_walk_subclasses(&walk);
		break;
	case PCIDB_TABLE_PROGIF:
		pcidb_walk_progifs(&walk);
		break;
	}

	ofmt_close(ofmt);
	pcidb_close(hdl);
	return (EXIT_SUCCESS);
}
