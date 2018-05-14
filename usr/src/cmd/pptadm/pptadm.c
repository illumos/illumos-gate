/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2018 Joyent, Inc.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <ofmt.h>
#include <err.h>

#include <libppt.h>

typedef enum field {
	PPT_DEV,
	PPT_VENDOR,
	PPT_DEVICE,
	PPT_SUBVENDOR,
	PPT_SUBDEVICE,
	PPT_REV,
	PPT_PATH,
	PPT_LABEL
} field_t;

const char *valname[] = {
	"dev",
	"vendor-id",
	"device-id",
	"subsystem-vendor-id",
	"subsystem-id",
	"revision-id",
	"path",
	"label"
};

static ofmt_cb_t print_field;

static ofmt_field_t fields[] = {
/* name,	field width, index, callback */
{ "DEV",	sizeof ("/dev/pptXX"), PPT_DEV, print_field },
{ "VENDOR",	sizeof ("VENDOR"), PPT_VENDOR, print_field },
{ "DEVICE",	sizeof ("DEVICE"), PPT_DEVICE, print_field },
{ "SUBVENDOR",	sizeof ("SUBVENDOR"), PPT_SUBVENDOR, print_field },
{ "SUBDEVICE",	sizeof ("SUBDEVICE"), PPT_SUBDEVICE, print_field },
{ "REV",	sizeof ("REV"), PPT_REV, print_field },
{ "PATH",	50, PPT_PATH, print_field },
{ "LABEL",	60, PPT_LABEL, print_field },
{ NULL,		0, 0, NULL },
};

static void
usage(const char *errmsg)
{
	if (errmsg != NULL)
		(void) fprintf(stderr, "pptadm: %s\n", errmsg);
	(void) fprintf(errmsg != NULL ? stderr : stdout,
	    "Usage:\n"
	    "pptadm list [ -j ]\n"
	    "pptadm list [-ap] [-o fields]\n");
	exit(errmsg != NULL ? EXIT_FAILURE : EXIT_SUCCESS);
}

/* PRINTFLIKE1 */
static void
die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
	va_end(ap);
}

static boolean_t
print_field(ofmt_arg_t *arg, char *buf, uint_t bufsize)
{
	nvlist_t *nvl = arg->ofmt_cbarg;
	nvpair_t *nvp = NULL;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		const char *name = nvpair_name(nvp);
		char *val = NULL;

		(void) nvpair_value_string(nvp, &val);

		if (strcmp(name, valname[arg->ofmt_id]) != 0)
			continue;

		(void) snprintf(buf, bufsize, "%s", val);
		return (B_TRUE);
	}

	(void) snprintf(buf, bufsize, "--");
	return (B_TRUE);
}

static int
list(int argc, char *argv[])
{
	const char *fields_str = NULL;
	boolean_t parsable = B_FALSE;
	boolean_t json = B_FALSE;
	boolean_t all = B_FALSE;
	uint_t ofmtflags = 0;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;
	int opt;

	while ((opt = getopt(argc, argv, "ahjo:p")) != -1) {
		switch (opt) {
		case 'a':
			all = B_TRUE;
			break;
		case 'h':
			usage(NULL);
			break;
		case 'j':
			json = B_TRUE;
			break;
		case 'o':
			fields_str = optarg;
			break;
		case 'p':
			ofmtflags |= OFMT_PARSABLE;
			parsable = B_TRUE;
			break;
		default:
			usage("unrecognized option");
			break;
		}
	}

	if (optind == (argc - 1))
		usage("unused arguments");

	if (json && (parsable || fields_str != NULL))
		usage("-j option cannot be used with -p or -o options");

	if (fields_str == NULL) {
		if (parsable)
			usage("-o must be provided when using -p option");
		fields_str = "dev,vendor,device,path";
	}

	oferr = ofmt_open(fields_str, fields, ofmtflags, 0, &ofmt);

	ofmt_check(oferr, parsable, ofmt, die, warn);

	nvlist_t *nvl = all ? ppt_list() : ppt_list_assigned();
	nvpair_t *nvp = NULL;

	if (json) {
		if (printf("{\n\t\"devices\": [\n") < 0)
			err(EXIT_FAILURE, "failed to write JSON");
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		nvlist_t *props;

		(void) nvpair_value_nvlist(nvp, &props);

		if (json) {
			if (printf("\t\t") < 0)
				err(EXIT_FAILURE, "failed to write JSON");
			if (nvlist_print_json(stdout, props) < 0)
				err(EXIT_FAILURE, "failed to write JSON");
			if (nvlist_next_nvpair(nvl, nvp) != NULL)
				(void) printf(",\n");
		} else {
			ofmt_print(ofmt, props);
		}
	}

	if (json) {
		if (printf("\n\t]\n}\n") < 0)
			err(EXIT_FAILURE, "failed to write JSON");
	}

	nvlist_free(nvl);
	ofmt_close(ofmt);
	return (EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	if (argc == 1)
		return (list(argc - 1, argv));

	if (strcmp(argv[1], "list") == 0) {
		return (list(argc - 1, &argv[1]));
	} else {
		usage("unknown sub-command");
	}

	return (EXIT_SUCCESS);
}
