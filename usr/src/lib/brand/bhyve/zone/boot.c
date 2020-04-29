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
 * Copyright 2020 Joyent, Inc.
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
#include <libcustr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zone.h>

/* These two paths must be relative to the zone root. */
#define	BHYVE_DIR		"var/run/bhyve"
#define	BHYVE_ARGS_FILE		BHYVE_DIR "/" "zhyve.cmd"

#define	ZH_MAXARGS		100

#define	DEFAULT_BOOTROM		"/usr/share/bhyve/uefi-rom.bin"
#define	DEFAULT_BOOTROM_CSM	"/usr/share/bhyve/uefi-csm-rom.bin"

typedef enum {
	PCI_SLOT_HOSTBRIDGE = 0,
	PCI_SLOT_CD = 3,		/* Windows ahci allows slots 3 - 6 */
	PCI_SLOT_BOOT_DISK,
	PCI_SLOT_OTHER_DISKS,
	PCI_SLOT_NICS,
	PCI_SLOT_FBUF = 30,
	PCI_SLOT_LPC = 31,		/* Windows requires lpc in slot 31 */
} pci_slot_t;

static boolean_t debug;
static const char *zonename;
static const char *zonepath;

#define	dprintf(x) if (debug) (void)printf x

static char *
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

static boolean_t
is_env_true(const char *rsrc, const char *inst, const char *prop)
{
	char *val = get_zcfg_var(rsrc, inst, prop);

	return (val != NULL && strcmp(val, "true") == 0);
}

static boolean_t
is_env_string(const char *rsrc, const char *inst, const char *prop,
    const char *val)
{
	char *pval = get_zcfg_var(rsrc, inst, prop);

	return (pval != NULL && strcmp(pval, val) == 0);
}

static int
add_arg(int *argc, char **argv, const char *val)
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

static int
add_smbios(int *argc, char **argv)
{
	char smbios[MAXPATHLEN];
	struct utsname utsname;
	const char *version;
	const char *uuid;

	if ((uuid = getenv("_ZONECFG_uuid")) != NULL) {
		if (add_arg(argc, argv, "-U") != 0 ||
		    add_arg(argc, argv, uuid) != 0)
			return (1);
	}

	/*
	 * Look for something like joyent_20180329T120303Z.  A little mucky, but
	 * it's exactly what sysinfo does.
	 */
	(void) uname(&utsname);
	if (strncmp(utsname.version, "joyent_", strlen("joyent_")) == 0)
		version = utsname.version + strlen("joyent_");
	else
		version = "?";

	/*
	 * This is based upon the SMBIOS values we expose to KVM guests.
	 */
	(void) snprintf(smbios, sizeof (smbios),
	    "1,manufacturer=Joyent,product=SmartDC HVM,version=7.%s,"
	    "serial=%s,sku=001,family=Virtual Machine",
	    version, zonename);

	if (add_arg(argc, argv, "-B") != 0 ||
	    add_arg(argc, argv, smbios) != 0)
		return (1);

	return (0);
}

static int
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

static int
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

static int
parse_pcislot(const char *pcislot, uint_t *busp, uint_t *devp, uint_t *funcp)
{
	char junk;

	switch (sscanf(pcislot, "%u:%u:%u%c", busp, devp, funcp, &junk)) {
	case 3:
		break;
	case 2:
	case 1:
		*funcp = *devp;
		*devp = *busp;
		*busp = 0;
		break;
	default:
		(void) printf("Error: device %d has illegal PCI slot: %s\n",
		    *devp, pcislot);
		return (-1);
	}

	if (*busp > 255 || *devp > 31 || *funcp > 7) {
		(void) printf("Error: device %d has illegal PCI slot: %s\n",
		    *devp, pcislot);
		return (-1);
	}

	return (0);
}

/*
 * In the initial implementation, slot assignment was dynamic on every boot.
 * Now, each device resource can have a pci_slot property that will override
 * dynamic assignment.  The original behavior is preserved, but no effort is
 * made to detect or avoid conflicts between legacy behavior and new behavior.
 * When used with vmadm, this is not an issue, as it will update the zone
 * config at boot time to contain static assignments.
 */
static int
add_disk(char *disk, char *path, char *slotconf, size_t slotconf_len)
{
	static char *boot = NULL;
	static int next_cd = 0;
	static int next_other = 0;
	custr_t *sconfstr = NULL;
	const char *model = "virtio-blk";
	uint_t pcibus = 0, pcidev = 0, pcifn = 0;
	const char *slotstr;
	const char *guest_block_size = NULL;
	boolean_t isboot;
	boolean_t nodelete = B_FALSE;

	if (custr_alloc_buf(&sconfstr, slotconf, slotconf_len) == -1) {
		return (-1);
	}

	isboot = is_env_true("device", disk, "boot");
	if (isboot) {
		/* Allow at most one "primary" disk */
		if (boot != NULL) {
			(void) printf("Error: multiple boot disks: %s %s\n",
			    boot, path);
			goto fail;
		}
		boot = path;
	}

	if ((slotstr = get_zcfg_var("device", disk, "pci_slot")) != NULL) {
		if (parse_pcislot(slotstr, &pcibus, &pcidev, &pcifn) != 0) {
			goto fail;
		}
	} else {
		if (isboot) {
			pcidev = PCI_SLOT_BOOT_DISK;
			pcifn = 0;
		} else if (is_env_string("device", disk, "media", "cdrom")) {
			pcidev = PCI_SLOT_CD;
			pcifn = next_cd;
			next_cd++;
		} else {
			pcidev = PCI_SLOT_OTHER_DISKS;
			pcifn = next_other;
			next_other++;
		}
	}

	if (is_env_string("device", disk, "model", "virtio")) {
		model = "virtio-blk";
		/*
		 * bhyve's blockif code refers to the UNMAP/DISCARD/TRIM
		 * feature as 'delete' and so 'nodelete' is used by
		 * bhyve to disable the feature. We use 'trim' for
		 * interfaces we expose to the operator as that seems to
		 * be the most familiar name for the operation (and less
		 * likely to cause confusion).
		 */
		nodelete = is_env_true("device", disk, "notrim");
		guest_block_size = get_zcfg_var("device", disk,
		    "guest_block_size");

		/* Treat a 0 size to mean the whatever the volume advertises */
		if (guest_block_size != NULL &&
		    strcmp(guest_block_size, "0") == 0) {
			guest_block_size = NULL;
		}
	} else if (is_env_string("device", disk, "model", "nvme")) {
		model = "nvme";
	} else if (is_env_string("device", disk, "model", "ahci")) {
		if (is_env_string("device", disk, "media", "cdrom")) {
			model = "ahci-cd";
		} else {
			model = "ahci-hd";
		}
	} else {
		(void) printf("Error: unknown disk model '%s'\n", model);
		goto fail;
	}

	if (custr_append_printf(sconfstr, "%u:%u:%u,%s,%s",
	    pcibus, pcidev, pcifn, model, path) == -1) {
		(void) printf("Error: disk path '%s' too long\n", path);
		goto fail;
	}

	if (nodelete && custr_append(sconfstr, ",nodelete") == -1) {
		(void) printf("Error: too many disk options\n");
		goto fail;
	}

	if (guest_block_size != NULL && custr_append_printf(sconfstr,
	    ",sectorsize=%s", guest_block_size) == -1) {
		(void) printf("Error: too many disk options\n");
		goto fail;
	}

	custr_free(sconfstr);
	return (0);

fail:
	custr_free(sconfstr);
	return (-1);
}

static int
add_ppt(int *argc, char **argv, char *ppt, char *path, char *slotconf,
    size_t slotconf_len)
{
	static boolean_t wired = B_FALSE;
	static boolean_t acpi = B_FALSE;
	uint_t bus = 0, dev = 0, func = 0;
	char *pcislot;

	pcislot = get_zcfg_var("device", ppt, "pci_slot");

	if (pcislot == NULL) {
		(void) printf("Error: device %s has no PCI slot\n", ppt);
		return (-1);
	}

	if (parse_pcislot(pcislot, &bus, &dev, &func) != 0) {
		return (-1);
	}

	if (bus > 0) {
		if (!acpi && add_arg(argc, argv, "-A") != 0)
			return (-1);
		acpi = B_TRUE;
	}

	if (!wired && add_arg(argc, argv, "-S") != 0)
		return (-1);

	wired = B_TRUE;

	if (snprintf(slotconf, slotconf_len, "%d:%d:%d,passthru,%s",
	    bus, dev, func, path) >= slotconf_len) {
		(void) printf("Error: device path '%s' too long\n", path);
		return (-1);
	}

	return (0);
}

static int
add_devices(int *argc, char **argv)
{
	char *devices;
	char *dev;
	char *lasts;
	char slotconf[MAXNAMELEN];

	if ((devices = get_zcfg_var("device", "resources", NULL)) == NULL) {
		return (0);
	}

	for (dev = strtok_r(devices, " ", &lasts); dev != NULL;
	    dev = strtok_r(NULL, " ", &lasts)) {
		int ret;
		char *path;
		char *model;

		/* zoneadmd is not careful about a trailing delimiter. */
		if (dev[0] == '\0') {
			continue;
		}

		if ((path = get_zcfg_var("device", dev, "path")) == NULL) {
			(void) printf("Error: device %s has no path\n", dev);
			return (-1);
		}

		if ((model = get_zcfg_var("device", dev, "model")) == NULL) {
			(void) printf("Error: device %s has no model\n", dev);
			return (-1);
		}

		if (strcmp(model, "passthru") == 0) {
			ret = add_ppt(argc, argv, dev, path, slotconf,
			    sizeof (slotconf));
		} else {
			ret = add_disk(dev, path, slotconf, sizeof (slotconf));
		}

		if (ret != 0)
			return (-1);

		if (add_arg(argc, argv, "-s") != 0 ||
		    add_arg(argc, argv, slotconf) != 0) {
			return (-1);
		}
	}

	return (0);
}

static int
add_nets(int *argc, char **argv)
{
	char *nets;
	char *net;
	char *lasts;
	int nextpcifn = 1;		/* 0 reserved for primary */
	char slotconf[MAXNAMELEN];
	char *primary = NULL;

	if ((nets = get_zcfg_var("net", "resources", NULL)) == NULL ||
	    strcmp(nets, "") == 0) {
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

	/* Make sure there is a "primary" net */
	if (primary == NULL) {
		(void) printf("Error: no primary net has been specified\n");
		return (-1);
	}

	return (0);
}

static int
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
			if (strcmp(val, "bios") == 0) {
				val = DEFAULT_BOOTROM_CSM;
			} else if (strcmp(val, "uefi") == 0) {
				val = DEFAULT_BOOTROM;
			}
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
		    add_arg(argc, argv, "bootrom," DEFAULT_BOOTROM_CSM) != 0) {
			return (-1);
		}
	}

	return (0);
}

static int
add_hostbridge(int *argc, char **argv)
{
	char conf[MAXPATHLEN];
	char *model = NULL;
	boolean_t raw_config = B_FALSE;

	if ((model = get_zcfg_var("attr", "hostbridge", NULL)) != NULL) {
		/* Easy bypass for doing testing */
		if (strcmp("none", model) == 0) {
			return (0);
		}

		if (strchr(model, '=') != NULL) {
			/*
			 * If the attribute contains '=', assume the creator
			 * wants total control over the config.  Do not prepend
			 * the value with 'model='.
			 */
			raw_config = B_TRUE;
		}
	}

	/* Default to Natoma if nothing else is specified */
	if (model == NULL) {
		model = "i440fx";
	}

	(void) snprintf(conf, sizeof (conf), "%d,hostbridge,%s%s",
	    PCI_SLOT_HOSTBRIDGE, raw_config ? "" : "model=", model);
	if (add_arg(argc, argv, "-s") != 0 ||
	    add_arg(argc, argv, conf) != 0) {
		return (-1);
	}
	return (0);
}

static int
add_bhyve_extra_opts(int *argc, char **argv)
{
	char *val;
	char *tok;
	char *lasts;

	if ((val = get_zcfg_var("attr", "bhyve_extra_opts", NULL)) == NULL) {
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

#define	INVALID_CHAR	(char)(255)

static char
decode_char(char encoded)
{
	if (encoded >= 'A' && encoded <= 'Z')
		return (encoded - 'A');
	if (encoded >= 'a' && encoded <= 'z')
		return (encoded - 'a' + 26);
	if (encoded >= '0' && encoded <= '9')
		return (encoded - '0' + 52);
	if (encoded == '+')
		return (62);
	if (encoded == '/')
		return (63);
	if (encoded == '=')
		return (0);
	return (INVALID_CHAR);
}

static int
add_base64(custr_t *cus, const char *b64)
{
	size_t b64len = strlen(b64);

	if (b64len == 0 || b64len % 4 != 0)
		return (-1);

	while (b64len > 0) {
		uint_t padding = 0;
		char c0 = decode_char(b64[0]);
		char c1 = decode_char(b64[1]);
		char c2 = decode_char(b64[2]);
		char c3 = decode_char(b64[3]);

		if (c0 == INVALID_CHAR || c1 == INVALID_CHAR ||
		    c2 == INVALID_CHAR || c3 == INVALID_CHAR) {
			(void) printf("Error: base64 value contains invalid "
			    "character(s)\n");
			return (-1);
		}

		/*
		 * For each block of 4 input characters, an '=' should
		 * only appear as the last two characters.
		 */
		if (b64[0] == '=' || b64[1] == '=') {
			(void) printf("Error: base64 value contains invalid "
			    "padding\n");
			return (-1);
		}

		if (b64len == 4) {
			/*
			 * We can end with '==' or '=', but never '='
			 * followed by something else.
			 */
			if (b64[2] == '=') {
				if (b64[3] != '=') {
					(void) printf("Error: base64 value "
					    "contains invalid padding\n");
					return (-1);
				}
				padding = 2;
			} else if (b64[3] == '=') {
				padding = 1;
			}
		}

		VERIFY0(custr_appendc(cus, c0 << 2 | c1 >> 4));
		if (padding < 2)
			VERIFY0(custr_appendc(cus, c1 << 4 | c2 >> 2));
		if (padding < 1)
			VERIFY0(custr_appendc(cus, c2 << 6 | c3));

		b64len -= 4;
		b64 += 4;
	}

	return (0);
}

/*
 * Adds the frame buffer and an xhci tablet to help with the pointer.
 */
static int
add_fbuf(int *argc, char **argv)
{
	char conf[MAXPATHLEN];
	custr_t *cconf = NULL;
	char *password = NULL;

	/*
	 * Do not add a frame buffer or tablet if VNC is disabled.
	 */
	if (is_env_string("attr", "vnc_port", NULL, "-1")) {
		return (0);
	}

	if (custr_alloc_buf(&cconf, conf, sizeof (conf)) != 0) {
		return (-1);
	}

	VERIFY0(custr_append_printf(cconf, "%d:0,fbuf,vga=off,unix=/tmp/vm.vnc",
	    PCI_SLOT_FBUF));

	password = get_zcfg_var("attr", "vnc_password", NULL);
	if (password != NULL) {
		VERIFY0(custr_append(cconf, ",password="));

		if (add_base64(cconf, password) != 0) {
			goto fail;
		}
	}

	if (add_arg(argc, argv, "-s") != 0 ||
	    add_arg(argc, argv, conf) != 0) {
		goto fail;
	}

	custr_reset(cconf);
	VERIFY0(custr_append_printf(cconf, "%d:1,xhci,tablet", PCI_SLOT_FBUF));

	if (add_arg(argc, argv, "-s") != 0 ||
	    add_arg(argc, argv, conf) != 0) {
		goto fail;
	}

	/*
	 * Since cconf was allocated using custr_alloc_buf() where 'conf'
	 * is the underlying fixed buffer for cconf, we can free cconf
	 * which in this instance will just free cconf, but _not_ the
	 * underlying fixed buffer (conf) which is left unchanged by
	 * custr_free().
	 */

	custr_free(cconf);
	return (0);

fail:
	custr_free(cconf);
	return (-1);
}

/* Must be called last */
static int
add_vmname(int *argc, char **argv)
{
	char buf[229];				/* VM_MAX_NAMELEN */
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
static int
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

static void
init_debug(void)
{
	char *val = getenv("_ZONEADMD_brand_debug");

	debug = (val != NULL && val[0] != '\0');
}

static int
setup_reboot(void)
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

	if (zone_setattr(zoneid, ZONE_ATTR_INITRESTART0, NULL, 0) < 0) {
		(void) printf("Error: bhyve zoneid %ld setattr failed: %s\n",
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
		"bhyve",	/* Squats on argv[0] */
		"-H",		/* vmexit on halt isns */
		NULL };
	int zhargc = 2;
	nvlist_t *nvl;
	char *nvbuf = NULL;
	size_t nvbuflen = 0;
	char zoneroot[MAXPATHLEN];
	int zrfd;

	init_debug();

	if (argc != 3) {
		(void) printf("Error: bhyve boot program called with "
		    "%d args, expecting 2\n", argc - 1);
		return (1);
	}
	zonename = argv[1];
	zonepath = argv[2];

	if (setup_reboot() < 0)
		return (1);

	if (add_smbios(&zhargc, (char **)&zhargv) != 0 ||
	    add_lpc(&zhargc, (char **)&zhargv) != 0 ||
	    add_hostbridge(&zhargc, (char **)&zhargv) != 0 ||
	    add_cpu(&zhargc, (char **)&zhargv) != 0 ||
	    add_ram(&zhargc, (char **)&zhargv) != 0 ||
	    add_devices(&zhargc, (char **)&zhargv) != 0 ||
	    add_nets(&zhargc, (char **)&zhargv) != 0 ||
	    add_bhyve_extra_opts(&zhargc, (char **)&zhargv) != 0 ||
	    add_fbuf(&zhargc, (char **)&zhargv) != 0 ||
	    add_vmname(&zhargc, (char **)&zhargv) != 0) {
		return (1);
	}

	/*
	 * This and other dynamically allocated resources are intentionally
	 * leaked.  It's a short-lived program and it will all get mopped up on
	 * exit.
	 */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string_array(nvl, "bhyve_args", zhargv, zhargc) != 0) {
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
		    "in zone: %s\n", BHYVE_DIR, strerror(errno));
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
