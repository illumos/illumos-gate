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
 * Use libzoneinfo to print a list of timezones for additional inspection. This
 * is paired with some of the DTrace script wrappers.
 */

#include <stdio.h>
#include <err.h>
#include <libzoneinfo.h>
#include <stdlib.h>
#include <sys/debug.h>

int
main(void)
{
	struct tz_continent *conts;

	if (get_tz_continents(&conts) < 0) {
		err(EXIT_FAILURE, "failed to get continent list");
	}

	for (struct tz_continent *ctnt = conts; ctnt != NULL;
	    ctnt = ctnt->ctnt_next) {
		struct tz_country *countries;

		if (get_tz_countries(&countries, ctnt) < 0) {
			err(EXIT_FAILURE, "failed to get countries for %s",
			    ctnt->ctnt_name);
		}

		for (struct tz_country *ctry = countries; ctry != NULL;
		    ctry = ctry->ctry_next) {
			struct tz_timezone *zones;

			if (get_timezones_by_country(&zones, ctry) < 0) {
				err(EXIT_FAILURE, "failed to get timezones for "
				    "%s/%s", ctnt->ctnt_name, ctry->ctry_code);
			}

			for (struct tz_timezone *tz = zones; tz != NULL;
			    tz = tz->tz_next) {
				(void) printf("%s\n", tz->tz_name);
			}

			VERIFY0(free_timezones(zones));
		}

		VERIFY0(free_tz_countries(countries));
	}

	VERIFY0(free_tz_continents(conts));
	return (0);
}
