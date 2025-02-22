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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Dump all of the information discovered by libzoneinfo in a way that's usable
 * for diffing. We use the following directory layout from the root:
 *
 * dir: <continent-name>
 *	file: info
 *	dir: <country-name>
 *		file: info
 *		file: <tz-name>
 */

#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libzoneinfo.h>
#include <sys/debug.h>
#include <errno.h>
#include <string.h>

static void
usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  zoneinfo_dump -d dir\n");
}

static void
dump_timezone(int dirfd, const struct tz_continent *cont,
    const struct tz_country *country, const struct tz_timezone *tz)
{
	int fd;
	char *name;
	FILE *f;

	name = strdup(tz->tz_name);
	if (name == NULL) {
		err(EXIT_FAILURE, "failed to duplicate tz name %s",
		    tz->tz_name);
	}

	for (size_t i = 0; i < strlen(name); i++) {
		if (name[i] == '/')
			name[i] = '-';
	}

	if ((fd = openat(dirfd, name, O_RDWR| O_CREAT | O_TRUNC, 0644)) < 0) {
		err(EXIT_FAILURE, "failed to create tz file for %s/%s/%s",
		    cont->ctnt_name, country->ctry_code, name);
	}

	if ((f = fdopen(fd, "w")) == NULL) {
		err(EXIT_FAILURE, "failed to create stdio stream for "
		    "tz %s/%s/%s file", cont->ctnt_name, country->ctry_code,
		    name);
	}

	(void) fprintf(f, "name: %s\n", tz->tz_name);
	(void) fprintf(f, "oname: %s\n", tz->tz_oname);
	(void) fprintf(f, "id: %s\n", tz->tz_id_desc);
	(void) fprintf(f, "desc: %s\n", tz->tz_display_desc);
	(void) fprintf(f, "lat: %d.%u.%u.%u\n", tz->tz_coord.lat_sign,
	    tz->tz_coord.lat_degree, tz->tz_coord.lat_minute,
	    tz->tz_coord.lat_second);
	(void) fprintf(f, "long: %d.%u.%u.%u\n", tz->tz_coord.long_sign,
	    tz->tz_coord.long_degree, tz->tz_coord.long_minute,
	    tz->tz_coord.long_second);

	VERIFY0(fflush(f));
	VERIFY0(fclose(f));

	free(name);
}

static void
dump_country(int cfd, const struct tz_continent *cont,
    struct tz_country *country)
{
	int dirfd, infofd, ret, found = 0;
	struct tz_timezone *zones;
	FILE *f;

	if (mkdirat(cfd, country->ctry_code, 0755) != 0 && errno != EEXIST) {
		err(EXIT_FAILURE, "failed to make country directory %s/%s",
		    cont->ctnt_name, country->ctry_code);
	}

	if ((dirfd = openat(cfd, country->ctry_code, O_DIRECTORY)) < 0) {
		err(EXIT_FAILURE, "failed to open country %s/%s",
		    cont->ctnt_name, country->ctry_code);
	}

	if ((infofd = openat(dirfd, "info", O_RDWR| O_CREAT | O_TRUNC, 0644)) <
	    0) {
		err(EXIT_FAILURE, "failed to create info file for country "
		    "%s/%s", cont->ctnt_name, country->ctry_code);
	}

	if ((f = fdopen(infofd, "w")) == NULL) {
		err(EXIT_FAILURE, "failed to create stdio stream for "
		    "country %s/%s info file", cont->ctnt_name,
		    country->ctry_code);
	}

	(void) fprintf(f, "name: %s\n", country->ctry_code);
	(void) fprintf(f, "id: %s\n", country->ctry_id_desc);
	(void) fprintf(f, "desc: %s\n", country->ctry_display_desc);
	VERIFY0(country->ctry_status);
	VERIFY0(fflush(f));
	VERIFY0(fclose(f));

	ret = get_timezones_by_country(&zones, country);
	if (ret < 0) {
		err(EXIT_FAILURE, "failed to get timezones for country %s/%s",
		    cont->ctnt_name, country->ctry_code);
	}

	for (struct tz_timezone *t = zones; t != NULL; t = t->tz_next,
	    found++) {
		dump_timezone(dirfd, cont, country, t);
	}

	if (ret != found) {
		errx(EXIT_FAILURE, "zoneinfo said %u timezones should exist "
		    "for country %s/%s, but found %u\n", ret, cont->ctnt_name,
		    country->ctry_code, found);
	}

	VERIFY0(free_timezones(zones));
	VERIFY0(close(dirfd));
}

static void
dump_continent(int root, struct tz_continent *cont)
{
	int dirfd, infofd, ret, found = 0;
	struct tz_country *country;
	FILE *f;

	if (mkdirat(root, cont->ctnt_name, 0755) != 0 &&
	    errno != EEXIST) {
		err(EXIT_FAILURE, "failed to make continent %s",
		    cont->ctnt_name);
	}

	if ((dirfd = openat(root, cont->ctnt_name, O_DIRECTORY)) < 0) {
		err(EXIT_FAILURE, "failed to open continent %s",
		    cont->ctnt_name);
	}

	if ((infofd = openat(dirfd, "info", O_RDWR| O_CREAT | O_TRUNC, 0644)) <
	    0) {
		err(EXIT_FAILURE, "failed to create info file for continent "
		    "%s", cont->ctnt_name);
	}

	if ((f = fdopen(infofd, "w")) == NULL) {
		err(EXIT_FAILURE, "failed to create stdio stream for "
		    "continent %s info file", cont->ctnt_name);
	}

	(void) fprintf(f, "name: %s\n", cont->ctnt_name);
	(void) fprintf(f, "id: %s\n", cont->ctnt_id_desc);
	(void) fprintf(f, "desc: %s\n", cont->ctnt_display_desc);
	VERIFY0(fflush(f));
	VERIFY0(fclose(f));

	ret = get_tz_countries(&country, cont);
	if (ret < 0) {
		err(EXIT_FAILURE, "failed to get countries for continent %s",
		    cont->ctnt_name);
	}

	for (struct tz_country *c = country; c != NULL; c = c->ctry_next,
	    found++) {
		dump_country(dirfd, cont, c);
	}

	if (ret != found) {
		errx(EXIT_FAILURE, "zoneinfo said %u countries should exist "
		    "for continent %s, but found %u\n", ret, cont->ctnt_name,
		    found);
	}

	/* For each Country */
	VERIFY0(free_tz_countries(country));
	VERIFY0(close(dirfd));
}

int
main(int argc, char *argv[])
{
	int c, dirfd, ret, found = 0;
	const char *base = NULL;
	struct tz_continent *conts;

	while ((c = getopt(argc, argv, ":d:")) != -1) {
		switch (c) {
		case 'd':
			base = optarg;
			break;
		case '?':
			usage("option -%c requires an argument", optopt);
			exit(EXIT_FAILURE);
		case ':':
			usage("unknown option: -%c", optopt);
			exit(EXIT_FAILURE);
		}
	}

	if (base == NULL) {
		errx(EXIT_FAILURE, "missing required directory, please use "
		    "the -d flag");
	}

	if ((dirfd = open(base, O_RDONLY | O_DIRECTORY)) < 0) {
		err(EXIT_FAILURE, "failed to open directory %s", base);
	}

	ret = get_tz_continents(&conts);
	if (ret < 0) {
		err(EXIT_FAILURE, "failed to get continents");
	}

	for (struct tz_continent *c = conts; c != NULL; c = c->ctnt_next,
	    found++) {
		dump_continent(dirfd, c);
	}

	if (found != ret) {
		errx(EXIT_FAILURE, "zoneinfo said %u continents should exist, "
		    "but found %u\n", ret, found);
	}

	VERIFY0(free_tz_continents(conts));

	return (0);
}
