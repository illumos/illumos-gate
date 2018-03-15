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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * This program runs as a child of zoneadmd, which sets a variety of
 * _ZONECFG_<resource>_<instance> properties so that child processes don't have
 * to parse xml.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zone.h>

/* These two paths must be relative to the zone root. */
#define	BHYVE_DIR		"var/run/bhyve"
#define	BHYVE_ARGS_FILE		BHYVE_DIR "/" "zhyve.cmd"

#define	ZH_MAXARGS		100

#define	DEFAULT_BOOTROM		"/usr/share/bhyve/uefi-csm-rom.bin"

typedef enum {
	PCI_SLOT_HOSTBRIDGE = 0,	/* Not used here, but reserved */
	PCI_SLOT_LPC,
	PCI_SLOT_CD,
	PCI_SLOT_BOOT_DISK,
	PCI_SLOT_OTHER_DISKS,
	PCI_SLOT_NICS
} pci_slot_t;

boolean_t debug;

#define	dprintf(x) if (debug) (void)printf x

char *
get_zcfg_var(const char *rsrc, const char *inst, const char *prop)
{
	char envvar[MAXNAMELEN];
	char *ret;

	if (prop == NULL) {
		if (snprintf(envvar, sizeof (envvar), "_ZONECFG_%s_%s",
		    rsrc, inst) >= sizeof (envvar)) {
			return (NULL);
		}
	} else {
		if (snprintf(envvar, sizeof (envvar), "_ZONECFG_%s_%s_%s",
		    rsrc, inst, prop) >= sizeof (envvar)) {
			return (NULL);
		}
	}

	ret = getenv(envvar);

	dprintf(("%s: '%s=%s'\n", __func__, envvar, ret ? ret : "<null>"));

	return (ret);
}

boolean_t
is_env_true(const char *rsrc, const char *inst, const char *prop)
{
	char *val = get_zcfg_var(rsrc, inst, prop);

	return (val != NULL && strcmp(val, "true") == 0);
}

int
add_arg(int *argc, char **argv, char *val)
{
	if (*argc >= ZH_MAXARGS) {
		(void) printf("Error: too many arguments\n");
		return (1);
	}
	argv[*argc] = strdup(val);
	assert(argv[*argc] != NULL);
	dprintf(("%s: argv[%d]='%s'\n", __func__, *argc, argv[*argc]));
	(*argc)++;
	return (0);
}

int
add_cpu(int *argc, char **argv)
{
	char *val;

	if ((val = get_zcfg_var("attr", "vcpus", NULL)) != NULL) {
		if (add_arg(argc, argv, "-c") != 0 ||
		    add_arg(argc, argv, val) != 0) {
			return (1);
		}
	}
	return (0);
}

int
add_ram(int *argc, char **argv)
{
	char *val;

	if ((val = get_zcfg_var("attr", "ram", NULL)) != NULL) {
		if (add_arg(argc, argv, "-m") != 0 ||
		    add_arg(argc, argv, val) != 0) {
			return (1);
		}
	}
	return (0);
}

int
add_disks(int *argc, char **argv)
{
	char *disks;
	char *disk;
	char *lasts;
	int next_cd = 0;
	int next_other = 0;
	char slotconf[MAXNAMELEN];
	char *boot = NULL;

	if ((disks = get_zcfg_var("device", "resources", NULL)) == NULL) {
		return (0);
	}

	for (disk = strtok_r(disks, " ", &lasts); disk != NULL;
	    disk = strtok_r(NULL, " ", &lasts)) {
		int pcislot;
		int pcifn;
		char *path;

		/* zoneadmd is not careful about a trailing delimiter. */
		if (disk[0] == '\0') {
			continue;
		}

		if ((path = get_zcfg_var("device", disk, "path")) == NULL) {
			(void) printf("Error: disk %s has no path\n", disk);
			return (-1);
		}

		/* Allow at most one "primary" disk */
		if (is_env_true("device", disk, "boot")) {
			if (boot != NULL) {
				(void) printf("Error: "
				    "multiple boot disks: %s %s\n",
				    boot, path);
				return (-1);
			}
			boot = path;
			pcislot = PCI_SLOT_BOOT_DISK;
			pcifn = 0;
		} else if (is_env_true("device", disk, "cdrom")) {
			pcislot = PCI_SLOT_CD;
			pcifn = next_cd;
			next_cd++;
		} else {
			pcislot = PCI_SLOT_OTHER_DISKS;
			pcifn = next_other;
			next_other++;
		}

		if (snprintf(slotconf, sizeof (slotconf),
		    "%d:%d,virtio-blk,%s", pcislot, pcifn, path) >=
		    sizeof (slotconf)) {
			(void) printf("Error: disk path '%s' too long\n", path);
			return (-1);
		}

		if (add_arg(argc, argv, "-s") != 0 ||
		    add_arg(argc, argv, slotconf) != 0) {
			return (-1);
		}
	}

	return (0);
}

int
add_nets(int *argc, char **argv)
{
	char *nets;
	char *net;
	char *lasts;
	int nextpcifn = 1;		/* 0 reserved for primary */
	char slotconf[MAXNAMELEN];
	char *primary = NULL;

	if ((nets = get_zcfg_var("net", "resources", NULL)) == NULL) {
		return (0);
	}

	for (net = strtok_r(nets, " ", &lasts); net != NULL;
	    net = strtok_r(NULL, " ", &lasts)) {
		int pcifn;

		/* zoneadmd is not careful about a trailing delimiter. */
		if (net[0] == '\0') {
			continue;
		}

		/* Allow at most one "primary" net */
		if (is_env_true("net", net, "primary")) {
			if (primary != NULL) {
				(void) printf("Error: "
				    "multiple primary nets: %s %s\n",
				    primary, net);
				return (-1);
			}
			primary = net;
			pcifn = 0;
		} else {
			pcifn = nextpcifn;
			nextpcifn++;
		}

		if (snprintf(slotconf, sizeof (slotconf),
		    "%d:%d,virtio-net-viona,%s", PCI_SLOT_NICS, pcifn, net) >=
		    sizeof (slotconf)) {
			(void) printf("Error: net '%s' too long\n", net);
			return (-1);
		}

		if (add_arg(argc, argv, "-s") != 0 ||
		    add_arg(argc, argv, slotconf) != 0) {
			return (-1);
		}
	}

	return (0);
}

int
add_lpc(int *argc, char **argv)
{
	char *lpcdevs[] = { "bootrom", "com1", "com2", NULL };
	const int bootrom_idx = 0;
	int i;
	char *val;
	char conf[MAXPATHLEN];
	boolean_t found_bootrom = B_FALSE;

	assert(strcmp(lpcdevs[bootrom_idx], "bootrom") == 0);

	(void) snprintf(conf, sizeof (conf), "%d,lpc", PCI_SLOT_LPC);
	if (add_arg(argc, argv, "-s") != 0 ||
	    add_arg(argc, argv, conf) != 0) {
		return (-1);
	}

	for (i = 0; lpcdevs[i] != NULL; i++) {
		if ((val = get_zcfg_var("attr", lpcdevs[i], NULL)) == NULL) {
			continue;
		}
		if (i == bootrom_idx) {
			found_bootrom = B_TRUE;
		}
		if (snprintf(conf, sizeof (conf), "%s,%s", lpcdevs[i], val) >=
		    sizeof (conf)) {
			(void) printf("Error: value of attr '%s' too long\n",
			    lpcdevs[i]);
			return (-1);
		}
		if (add_arg(argc, argv, "-l") != 0 ||
		    add_arg(argc, argv, conf) != 0) {
			return (-1);
		}
	}

	if (!found_bootrom) {
		if (add_arg(argc, argv, "-l") != 0 ||
		    add_arg(argc, argv, "bootrom," DEFAULT_BOOTROM) != 0) {
			return (-1);
		}
	}

	return (0);
}

int
add_bhyve_opts(int *argc, char **argv)
{
	char *val;
	char *tok;
	char *lasts;

	if ((val = get_zcfg_var("attr", "bhyve_opts", NULL)) == NULL) {
		return (0);
	}

	val = strdup(val);
	if (val == NULL) {
		(void) printf("Error: strdup failed\n");
		return (-1);
	}

	for (tok = strtok_r(val, " \t", &lasts); tok != NULL;
	    tok = strtok_r(NULL, " \t", &lasts)) {
		if (tok[0] == '\0') {
			continue;
		}
		if (add_arg(argc, argv, tok) != 0) {
			return (-1);
		}
	}

	free(val);
	return (0);
}

/* Must be called last */
int
add_vmname(int *argc, char **argv)
{
	char buf[32];				/* VM_MAX_NAMELEN */
	char *val = getenv("_ZONECFG_did");

	if (val == NULL || val[0] == '\0') {
		val = "SYSbhyve-unknown";
	} else {
		(void) snprintf(buf, sizeof (buf), "SYSbhyve-%s", val);
		val = buf;
	}
	if (add_arg(argc, argv, val) != 0) {
		return (-1);
	}
	return (0);
}

/*
 * Write the entire buffer or return an error.  This function could be more
 * paranoid and call fdsync() at the end.  That's not really need for this use
 * case because it is being written to tmpfs.
 */
int
full_write(int fd, char *buf, size_t buflen)
{
	ssize_t nwritten;
	size_t totwritten = 0;

	while (totwritten < buflen) {
		nwritten = write(fd, buf + totwritten, buflen - totwritten);
		if (nwritten < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return (-1);
		}
		assert(nwritten > 0);
		totwritten += nwritten;
	}
	assert(totwritten == buflen);

	return (0);
}

void
init_debug(void)
{
	char *val = getenv("_ZONEADMD_brand_debug");

	debug = (val != NULL && val[0] != '\0');
}

static int
setup_reboot(char *zonename)
{
	zoneid_t	zoneid;

	if ((zoneid = getzoneidbyname(zonename)) < 0) {
		(void) printf("Error: bhyve zoneid (%s) does not exist\n",
		    zonename);
		return (-1);
	}

	if (zoneid == GLOBAL_ZONEID) {
		(void) printf("Error: bhyve global zoneid (%s)\n", zonename);
		return (-1);
	}

	if (zone_setattr(zoneid, ZONE_ATTR_INITREBOOT, NULL, 0) < 0 ||
	    zone_setattr(zoneid, ZONE_ATTR_INITRESTART0, NULL, 0) < 0) {
		(void) printf("Error: bhyve zoneid %d setattr failed: %s\n",
		    zoneid, strerror(errno));
		return (-1);
	}

	return (0);
}

int
main(int argc, char **argv)
{
	int fd, err;
	char *zhargv[ZH_MAXARGS] = {
		"zhyve",	/* Squats on argv[0] */
		"-H",		/* vmexit on halt isns */
		"-B", "1,product=SmartDC HVM",
		NULL };
	int zhargc;
	nvlist_t *nvl;
	char *nvbuf = NULL;
	size_t nvbuflen = 0;
	char zoneroot[MAXPATHLEN];
	int zrfd;
	char *zonename;
	char *zonepath;

	init_debug();

	if (argc != 3) {
		(void) printf("Error: bhyve boot program called with "
		    "%d args, expecting 2\n", argc - 1);
		return (1);
	}
	zonename = argv[1];
	zonepath = argv[2];

	if (setup_reboot(zonename) < 0)
		return (1);

	for (zhargc = 0; zhargv[zhargc] != NULL; zhargc++) {
		dprintf(("def_arg: argv[%d]='%s'\n", zhargc, zhargv[zhargc]));
	}

	if (add_lpc(&zhargc, (char **)&zhargv) != 0 ||
	    add_cpu(&zhargc, (char **)&zhargv) != 0 ||
	    add_ram(&zhargc, (char **)&zhargv) != 0 ||
	    add_disks(&zhargc, (char **)&zhargv) != 0 ||
	    add_nets(&zhargc, (char **)&zhargv) != 0 ||
	    add_bhyve_opts(&zhargc, (char **)&zhargv) != 0 ||
	    add_vmname(&zhargc, (char **)&zhargv) != 0) {
		return (1);
	}

	/*
	 * This and other dynamically allocated resources are intentionally
	 * leaked.  It's a short-lived program and it will all get mopped up on
	 * exit.
	 */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string_array(nvl, "zhyve_args", zhargv, zhargc) != 0) {
		(void) printf("Error: failed to create nvlist: %s\n",
		    strerror(errno));
		return (1);
	}

	if (debug) {
		dprintf(("packing nvlist:\n"));
		nvlist_print(stdout, nvl);
	}

	err = nvlist_pack(nvl, &nvbuf, &nvbuflen, NV_ENCODE_XDR, 0);
	if (err != 0) {
		(void) printf("Error: failed to pack nvlist: %s\n",
		    strerror(err));
		return (1);
	}

	if (snprintf(zoneroot, sizeof (zoneroot), "%s/root", zonepath) >=
	    sizeof (zoneroot)) {
		(void) printf("Error: zonepath '%s' too long\n", zonepath);
		return (1);
	}

	if ((zrfd = open(zoneroot, O_RDONLY|O_SEARCH)) < 0) {
		(void) printf("Error: cannot open zone root '%s': %s\n",
		    zoneroot, strerror(errno));
		return (1);
	}

	/*
	 * This mkdirat() and the subsequent openat() are only safe because the
	 * zone root is always under the global zone's exclusive control (always
	 * read-only in all zones) and the writable directory is a tmpfs file
	 * system that was just mounted and no zone code has run yet.
	 */
	if (mkdirat(zrfd, BHYVE_DIR, 0700) != 0 && errno != EEXIST) {
		(void) printf("Error: failed to create directory %s "
		    "in zone: %s\n" BHYVE_DIR, strerror(errno));
		return (1);
	}

	fd = openat(zrfd, BHYVE_ARGS_FILE, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		(void) printf("Error: failed to create file %s in zone: %s\n",
		    BHYVE_ARGS_FILE, strerror(errno));
		return (1);
	}
	if (full_write(fd, nvbuf, nvbuflen) != 0) {
		(void) printf("Error: failed to write %s: %s\n",
		    BHYVE_ARGS_FILE, strerror(errno));
		(void) unlink(BHYVE_ARGS_FILE);
		return (1);
	}

	return (0);
}
