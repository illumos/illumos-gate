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
 * Copyright (c) 2013 Joyent Inc., All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>

#include <libdiskmgt.h>
#include <sys/nvpair.h>
#include <sys/param.h>
#include <sys/ccompile.h>

#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <fm/topo_list.h>
#include <sys/fm/protocol.h>
#include <modules/common/disk/disk.h>

typedef struct di_opts {
	boolean_t di_scripted;
	boolean_t di_parseable;
	boolean_t di_physical;
	boolean_t di_condensed;
} di_opts_t;

typedef struct di_phys {
	const char *dp_dev;
	const char *dp_serial;
	const char *dp_slotname;
	int dp_chassis;
	int dp_slot;
	int dp_faulty;
	int dp_locate;
} di_phys_t;

static void __NORETURN
fatal(int rv, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(rv);
}

static void
usage(const char *execname)
{
	(void) fprintf(stderr, "Usage: %s [-Hp] [{-c|-P}]\n", execname);
}

static void
nvlist_query_string(nvlist_t *nvl, const char *label, char **val)
{
	if (nvlist_lookup_string(nvl, label, val) != 0)
		*val = "-";
}

static const char *
display_string(const char *label)
{
	return ((label) ? label : "-");
}

static const char *
display_tristate(int val)
{
	if (val == 0)
		return ("no");
	if (val == 1)
		return ("yes");

	return ("-");
}

static char
condensed_tristate(int val, char c)
{
	if (val == 0)
		return ('-');
	if (val == 1)
		return (c);

	return ('?');
}
static int
disk_walker(topo_hdl_t *hp, tnode_t *np, void *arg)
{
	di_phys_t *pp = arg;
	tnode_t *pnp;
	tnode_t *ppnp;
	topo_faclist_t fl;
	topo_faclist_t *lp;
	int err;
	topo_led_state_t mode;
	topo_led_type_t type;
	char *name, *slotname, *serial;

	if (strcmp(topo_node_name(np), DISK) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_prop_get_string(np, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_LOGICAL_DISK_NAME, &name, &err) != 0) {
		return (TOPO_WALK_NEXT);
	}

	if (strcmp(name, pp->dp_dev) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_prop_get_string(np, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_SERIAL_NUM, &serial, &err) == 0) {
		pp->dp_serial = serial;
	}

	pnp = topo_node_parent(np);
	ppnp = topo_node_parent(pnp);
	if (strcmp(topo_node_name(pnp), BAY) == 0) {
		if (topo_node_facility(hp, pnp, TOPO_FAC_TYPE_INDICATOR,
		    TOPO_FAC_TYPE_ANY, &fl, &err) == 0) {
			for (lp = topo_list_next(&fl.tf_list); lp != NULL;
			    lp = topo_list_next(lp)) {
				uint32_t prop;

				if (topo_prop_get_uint32(lp->tf_node,
				    TOPO_PGROUP_FACILITY, TOPO_FACILITY_TYPE,
				    &prop, &err) != 0) {
					continue;
				}
				type = (topo_led_type_t)prop;

				if (topo_prop_get_uint32(lp->tf_node,
				    TOPO_PGROUP_FACILITY, TOPO_LED_MODE,
				    &prop, &err) != 0) {
					continue;
				}
				mode = (topo_led_state_t)prop;

				switch (type) {
				case TOPO_LED_TYPE_SERVICE:
					pp->dp_faulty = mode ? 1 : 0;
					break;
				case TOPO_LED_TYPE_LOCATE:
					pp->dp_locate = mode ? 1 : 0;
					break;
				default:
					break;
				}
			}
		}

		if (topo_prop_get_string(pnp, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, &slotname, &err) == 0) {
			pp->dp_slotname = slotname;
		}

		pp->dp_slot = topo_node_instance(pnp);
	}

	pp->dp_chassis = topo_node_instance(ppnp);

	return (TOPO_WALK_TERMINATE);
}

static void
populate_physical(topo_hdl_t *hp, di_phys_t *pp)
{
	int err;
	topo_walk_t *wp;

	pp->dp_faulty = pp->dp_locate = -1;
	pp->dp_chassis = pp->dp_slot = -1;

	err = 0;
	wp = topo_walk_init(hp, FM_FMRI_SCHEME_HC, disk_walker, pp, &err);
	if (wp == NULL) {
		fatal(-1, "unable to initialise topo walker: %s",
		    topo_strerror(err));
	}

	while ((err = topo_walk_step(wp, TOPO_WALK_CHILD)) == TOPO_WALK_NEXT)
		;

	if (err == TOPO_WALK_ERR)
		fatal(-1, "topo walk failed");

	topo_walk_fini(wp);
}

static void
enumerate_disks(di_opts_t *opts)
{
	topo_hdl_t *hp;
	dm_descriptor_t *media;
	int err, i;
	int filter[] = { DM_DT_FIXED, -1 };
	dm_descriptor_t *disk, *controller;
	nvlist_t *mattrs, *dattrs, *cattrs = NULL;

	uint64_t size, total;
	uint32_t blocksize;
	double total_in_GiB;
	char sizestr[32];
	char slotname[32];
	char statestr[8];

	char *vid, *pid, *opath, *c, *ctype = NULL;
	boolean_t removable;
	boolean_t ssd;
	char device[MAXPATHLEN];
	di_phys_t phys;
	size_t len;

	err = 0;
	if ((media = dm_get_descriptors(DM_MEDIA, filter, &err)) == NULL) {
		fatal(-1, "failed to obtain media descriptors: %s\n",
		    strerror(err));
	}

	err = 0;
	hp = topo_open(TOPO_VERSION, NULL, &err);
	if (hp == NULL) {
		fatal(-1, "unable to obtain topo handle: %s",
		    topo_strerror(err));
	}

	err = 0;
	(void) topo_snap_hold(hp, NULL, &err);
	if (err != 0) {
		fatal(-1, "unable to hold topo snapshot: %s",
		    topo_strerror(err));
	}

	for (i = 0; media != NULL && media[i] != NULL; i++) {
		if ((disk = dm_get_associated_descriptors(media[i],
		    DM_DRIVE, &err)) == NULL) {
			continue;
		}

		mattrs = dm_get_attributes(media[i], &err);
		err = nvlist_lookup_uint64(mattrs, DM_SIZE, &size);
		assert(err == 0);
		err = nvlist_lookup_uint32(mattrs, DM_BLOCKSIZE, &blocksize);
		assert(err == 0);
		nvlist_free(mattrs);

		dattrs = dm_get_attributes(disk[0], &err);

		nvlist_query_string(dattrs, DM_VENDOR_ID, &vid);
		nvlist_query_string(dattrs, DM_PRODUCT_ID, &pid);
		nvlist_query_string(dattrs, DM_OPATH, &opath);

		removable = B_FALSE;
		if (nvlist_lookup_boolean(dattrs, DM_REMOVABLE) == 0)
			removable = B_TRUE;

		ssd = B_FALSE;
		if (nvlist_lookup_boolean(dattrs, DM_SOLIDSTATE) == 0)
			ssd = B_TRUE;

		if ((controller = dm_get_associated_descriptors(disk[0],
		    DM_CONTROLLER, &err)) != NULL) {
			cattrs = dm_get_attributes(controller[0], &err);
			nvlist_query_string(cattrs, DM_CTYPE, &ctype);
			ctype = strdup(ctype);
			for (c = ctype; *c != '\0'; c++)
				*c = toupper(*c);
		}

		/*
		 * Parse full device path to only show the device name,
		 * i.e. c0t1d0.  Many paths will reference a particular
		 * slice (c0t1d0s0), so remove the slice if present.
		 */
		if ((c = strrchr(opath, '/')) != NULL)
			(void) strlcpy(device, c + 1, sizeof (device));
		else
			(void) strlcpy(device, opath, sizeof (device));
		len = strlen(device);
		if (device[len - 2] == 's' &&
		    (device[len - 1] >= '0' && device[len - 1] <= '9'))
			device[len - 2] = '\0';

		bzero(&phys, sizeof (phys));
		phys.dp_dev = device;
		populate_physical(hp, &phys);

		/*
		 * The size is given in blocks, so multiply the number
		 * of blocks by the block size to get the total size,
		 * then convert to GiB.
		 */
		total = size * blocksize;

		if (opts->di_parseable) {
			(void) snprintf(sizestr, sizeof (sizestr),
			    "%llu", total);
		} else {
			total_in_GiB = (double)total /
			    1024.0 / 1024.0 / 1024.0;
			(void) snprintf(sizestr, sizeof (sizestr),
			    "%7.2f GiB", total_in_GiB);
		}

		if (opts->di_parseable) {
			(void) snprintf(slotname, sizeof (slotname), "%d,%d",
			    phys.dp_chassis, phys.dp_slot);
		} else if (phys.dp_slotname != NULL) {
			(void) snprintf(slotname, sizeof (slotname),
			    "[%d] %s", phys.dp_chassis, phys.dp_slotname);
		} else {
			slotname[0] = '-';
			slotname[1] = '\0';
		}

		if (opts->di_condensed) {
			(void) snprintf(statestr, sizeof (statestr), "%c%c%c%c",
			    condensed_tristate(phys.dp_faulty, 'F'),
			    condensed_tristate(phys.dp_locate, 'L'),
			    condensed_tristate(removable, 'R'),
			    condensed_tristate(ssd, 'S'));
		}

		if (opts->di_physical) {
			if (opts->di_scripted) {
				printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				    device, vid, pid,
				    display_string(phys.dp_serial),
				    display_tristate(phys.dp_faulty),
				    display_tristate(phys.dp_locate), slotname);
			} else {
				printf("%-22s  %-8s %-16s "
				    "%-20s %-3s %-3s %s\n",
				    device, vid, pid,
				    display_string(phys.dp_serial),
				    display_tristate(phys.dp_faulty),
				    display_tristate(phys.dp_locate), slotname);
			}
		} else if (opts->di_condensed) {
			if (opts->di_scripted) {
				printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				    ctype, device, vid, pid,
				    display_string(phys.dp_serial),
				    sizestr, statestr, slotname);
			} else {
				printf("%-7s %-22s  %-8s %-16s "
				    "%-20s\n\t%-13s %-4s %s\n",
				    ctype, device, vid, pid,
				    display_string(phys.dp_serial),
				    sizestr, statestr, slotname);
			}
		} else {
			if (opts->di_scripted) {
				printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				    ctype, device, vid, pid, sizestr,
				    display_tristate(removable),
				    display_tristate(ssd));
			} else {
				printf("%-7s %-22s  %-8s %-16s "
				    "%-13s %-3s %-3s\n", ctype, device,
				    vid, pid, sizestr,
				    display_tristate(removable),
				    display_tristate(ssd));
			}
		}

		free(ctype);
		nvlist_free(cattrs);
		nvlist_free(dattrs);
		dm_free_descriptors(controller);
		dm_free_descriptors(disk);
	}

	dm_free_descriptors(media);
	topo_snap_release(hp);
	topo_close(hp);
}

int
main(int argc, char *argv[])
{
	char c;

	di_opts_t opts = {
		.di_condensed = B_FALSE,
		.di_scripted = B_FALSE,
		.di_physical = B_FALSE,
		.di_parseable = B_FALSE
	};

	while ((c = getopt(argc, argv, ":cHPp")) != EOF) {
		switch (c) {
		case 'c':
			if (opts.di_physical) {
				usage(argv[0]);
				fatal(1, "-c and -P are mutually exclusive\n");
			}
			opts.di_condensed = B_TRUE;
			break;
		case 'H':
			opts.di_scripted = B_TRUE;
			break;
		case 'P':
			if (opts.di_condensed) {
				usage(argv[0]);
				fatal(1, "-c and -P are mutually exclusive\n");
			}
			opts.di_physical = B_TRUE;
			break;
		case 'p':
			opts.di_parseable = B_TRUE;
			break;
		case '?':
			usage(argv[0]);
			fatal(1, "unknown option -%c\n", optopt);
		default:
			fatal(-1, "unexpected error on option -%c\n", optopt);
		}
	}

	if (!opts.di_scripted) {
		if (opts.di_physical) {
			printf("DISK                    VID      PID"
			    "              SERIAL               FLT LOC"
			    " LOCATION\n");
		} else if (opts.di_condensed) {
			printf("TYPE    DISK                    VID      PID"
			    "              SERIAL\n");
			printf("\tSIZE          FLRS LOCATION\n");
		} else {
			printf("TYPE    DISK                    VID      PID"
			    "              SIZE          RMV SSD\n");
		}
	}

	enumerate_disks(&opts);

	return (0);
}
