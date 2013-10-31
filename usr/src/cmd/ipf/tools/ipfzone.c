/*
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * See the IPFILTER.LICENCE file for details on licensing.
 */


#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zone.h>

#include "netinet/ip_fil.h"
#include "ipfzone.h"

static ipfzoneobj_t	ipzo;
static boolean_t	do_setzone = 0;
static int		num_setzones = 0;

extern int	errno;
extern int	optind;
extern char	*optarg;

/*
 * Get the zonename if it's the last argument and set the zonename
 * in ipfzo to it
 */
void
getzonearg(int argc, char *argv[], const char *optstr)
{
	int c;

	/*
	 * getopt is also used here to set optind so that we can
	 * determine if the last argument belongs to a flag or is
	 * actually a zonename.
	 */
	while ((c = getopt(argc, argv, optstr)) != -1) {
		if (c == 'G')
			ipzo.ipfz_gz = 1;
	}

	if (optind < argc)
		setzonename(argv[optind]);

	/*
	 * Reset optind so the next getopt call will go through all of argv
	 * again.
	 */
	optind = 1;
}

/*
 * Get a -z option from argv and set the zonename in ipfzo accordingly
 */
void
getzoneopt(int argc, char *argv[], const char *optstr)
{
	int c;

	while ((c = getopt(argc, argv, optstr)) != -1) {
		if (c == 'G')
			setzonename_global(optarg);

		if (c == 'z')
			setzonename(optarg);
	}

	/*
	 * Reset optind so the next getopt call will go through all of argv
	 * again.
	 */
	optind = 1;
}

/*
 * Set the zonename in ipfzo to the given string
 */
void
setzonename(const char *zonename)
{
	memcpy(ipzo.ipfz_zonename, zonename, sizeof (ipzo.ipfz_zonename));
	do_setzone = B_TRUE;
	num_setzones++;
}

/*
 * Set the zonename in ipfo, and the gz flag to indicate that we want to
 * act on the GZ-controlled stack
 */
void
setzonename_global(const char *zonename)
{
	setzonename(zonename);
	ipzo.ipfz_gz = 1;
}

/*
 * Set the zone that all further ioctls will operate on
 */
int
setzone(int fd)
{
	if (!do_setzone)
		return (0);

	if (num_setzones > 1) {
		(void) fprintf(stderr,
		    "Only one of -G and -z may be set\n");
		return (-1);
	}

	if (ioctl(fd, SIOCIPFZONESET, &ipzo) == -1) {
		switch (errno) {
		case ENODEV:
			(void) fprintf(stderr,
			    "Could not find running zone: %s\n",
			    ipzo.ipfz_zonename);
			break;
		case EACCES:
			(void) fprintf(stderr,
			    "Permission denied setting zone: %s\n",
			    ipzo.ipfz_zonename);
			break;
		default:
			perror("Error setting zone");
		}
		return (-1);
	}

	return (0);
}
