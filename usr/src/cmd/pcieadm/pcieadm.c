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
 * PCIe shenanigans
 *
 * Currently this implements several different views at seeing into PCIe devices
 * and is designed to (hopefully) replace pcitool and be a vector for new system
 * functionality such as dealing with multicast filtering, ACS, etc.
 *
 * While most subcommands have their own implementations, there are a couple of
 * things that are worth bearing in mind:
 *
 *  1) Where possible, prefer the use of libofmt. In particular, having good,
 *  parsable output is important. New subcommands should strive to meet that.
 *
 *  2) Because we're often processing binary data (and it's good hygiene),
 *  subcommands should make sure to drop privileges as early as they can by
 *  calling pcieadm_init_privs(). More on privileges below.
 *
 * Privilege Management
 * --------------------
 *
 * In an attempt to minimize privilege exposure, but to allow subcommands
 * flexibility when required (e.g. show-cfgspace needs full privs to read from
 * the kernel), we have two privilege sets that we maintain. One which is the
 * minimial privs, which basically is a set that has stripped everything. This
 * is 'pia_priv_min'. The second is one that allows a subcommand to add in
 * privileges that it requires which will be left in the permitted set. These
 * are in 'pia_priv_eff'. It's important to know that this set is always
 * intersected with what the user actually has, so this is not meant to be a way
 * for a caller to get more privileges than they already have.
 *
 * A subcommand is expected to call pcieadm_init_privs() once they have
 * processed enough arguments that they can set an upper bound on privileges.
 * It's worth noting that a subcommand will be executed in an already minimial
 * environment; however, we will have already set up a libdevinfo handle for
 * them, which should make the need to do much more not so bad.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <err.h>
#include <libdevinfo.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/pci_tools.h>
#include <sys/pci.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/debug.h>
#include <upanic.h>
#include <libgen.h>
#include <stdnoreturn.h>

#include "pcieadm.h"

pcieadm_t pcieadm;
const char *pcieadm_progname;

void
pcieadm_init_privs(pcieadm_t *pcip)
{
	static const char *msg = "attempted to re-initialize privileges";
	if (pcip->pia_priv_init == NULL) {
		upanic(msg, strlen(msg));
	}

	priv_intersect(pcip->pia_priv_init, pcip->pia_priv_eff);

	if (setppriv(PRIV_SET, PRIV_PERMITTED, pcieadm.pia_priv_eff) != 0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	if (setppriv(PRIV_SET, PRIV_LIMIT, pcieadm.pia_priv_eff) != 0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	priv_freeset(pcip->pia_priv_init);
	pcip->pia_priv_init = NULL;
}

void
pcieadm_indent(void)
{
	pcieadm.pia_indent += 2;
}

void
pcieadm_deindent(void)
{
	VERIFY3U(pcieadm.pia_indent, >, 0);
	pcieadm.pia_indent -= 2;
}

void
pcieadm_print(const char *fmt, ...)
{
	va_list ap;

	if (pcieadm.pia_indent > 0) {
		(void) printf("%*s", pcieadm.pia_indent, "");
	}

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

void
pcieadm_ofmt_errx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
}

/*
 * We determine if a node is PCI in a two step process. The first is to see if
 * the node's name starts with pci, and has an additional character that
 * indicates it's not the synthetic root of the tree. However, the node name
 * changes for some classes of devices such as GPUs. As such, for those we try
 * to look at the compatible property and see if we have a pciexclass or
 * pciclass entry. We look specifically for the class to make sure that we don't
 * fall for the synthetic nodes that have a compatible property of
 * 'pciex_root_complex'.
 *
 * The compatible property is a single string that is actually a compressed
 * string. That is, there are multiple strings concatenated together in a single
 * pointer.
 */
static boolean_t
pcieadm_di_node_is_pci(di_node_t node)
{
	const char *name;
	char *compat;
	int nents;

	name = di_node_name(node);
	if (strncmp("pci", name, 3) == 0) {
		return (name[3] != '\0');
	}

	nents = di_prop_lookup_strings(DDI_DEV_T_ANY, node, "compatible",
	    &compat);
	if (nents <= 0) {
		return (B_FALSE);
	}

	for (int i = 0; i < nents; i++) {
		if (strncmp("pciclass,", compat, strlen("pciclass,")) == 0 ||
		    strncmp("pciexclass,", compat, strlen("pciexclass,")) ==
		    0) {
			return (B_TRUE);
		}

		compat += strlen(compat) + 1;
	}

	return (B_FALSE);
}

static int
pcieadm_di_walk_cb(di_node_t node, void *arg)
{
	pcieadm_di_walk_t *walk = arg;

	if (!pcieadm_di_node_is_pci(node)) {
		return (DI_WALK_CONTINUE);
	}

	return (walk->pdw_func(node, walk->pdw_arg));
}

static di_node_t
pcieadm_di_root(pcieadm_t *pcip)
{
	if (pcip->pia_root == DI_NODE_NIL) {
		pcip->pia_root = di_init("/", DINFOCPYALL);
		if (pcip->pia_root == DI_NODE_NIL) {
			err(EXIT_FAILURE, "failed to initialize devinfo tree");
		}
	}

	return (pcip->pia_root);
}

void
pcieadm_di_walk(pcieadm_t *pcip, pcieadm_di_walk_t *arg)
{
	(void) di_walk_node(pcieadm_di_root(pcip), DI_WALK_CLDFIRST, arg,
	    pcieadm_di_walk_cb);
}

/*
 * Attempt to find the nexus that corresponds to this device. To do this, we
 * walk up and walk the minors until we find a "reg" minor.
 */
void
pcieadm_find_nexus(pcieadm_t *pia)
{
	di_node_t cur;

	for (cur = di_parent_node(pia->pia_devi); cur != DI_NODE_NIL;
	    cur = di_parent_node(cur)) {
		di_minor_t minor = DI_MINOR_NIL;

		while ((minor = di_minor_next(cur, minor)) != DI_MINOR_NIL) {
			if (di_minor_spectype(minor) == S_IFCHR &&
			    strcmp(di_minor_name(minor), "reg") == 0) {
				pia->pia_nexus = cur;
				return;
			}
		}
	}
}

static int
pcieadm_find_dip_cb(di_node_t node, void *arg)
{
	char *path = NULL, *driver;
	char dinst[128], bdf[128], altbdf[128];
	int inst, nprop, *regs;
	pcieadm_t *pia = arg;

	path = di_devfs_path(node);
	if (path == NULL) {
		err(EXIT_FAILURE, "failed to construct devfs path for node: "
		    "%s", di_node_name(node));
	}

	driver = di_driver_name(node);
	inst = di_instance(node);
	if (driver != NULL && inst != -1) {
		(void) snprintf(dinst, sizeof (dinst), "%s%d", driver, inst);
	}

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "reg", &regs);
	if (nprop <= 0) {
		errx(EXIT_FAILURE, "failed to lookup regs array for %s",
		    path);
	}
	(void) snprintf(bdf, sizeof (bdf), "%x/%x/%x", PCI_REG_BUS_G(regs[0]),
	    PCI_REG_DEV_G(regs[0]), PCI_REG_FUNC_G(regs[0]));
	(void) snprintf(altbdf, sizeof (altbdf), "%02x/%02x/%02x",
	    PCI_REG_BUS_G(regs[0]), PCI_REG_DEV_G(regs[0]),
	    PCI_REG_FUNC_G(regs[0]));

	if (strcmp(pia->pia_devstr, path) == 0 ||
	    strcmp(pia->pia_devstr, bdf) == 0 ||
	    strcmp(pia->pia_devstr, altbdf) == 0 ||
	    (driver != NULL && inst != -1 &&
	    strcmp(pia->pia_devstr, dinst) == 0)) {
		if (pia->pia_devi != DI_NODE_NIL) {
			errx(EXIT_FAILURE, "device name matched two device "
			    "nodes: %s and %s", di_node_name(pia->pia_devi),
			    di_node_name(node));
		}

		pia->pia_devi = node;
	}

	if (path != NULL) {
		di_devfs_path_free(path);
	}

	return (DI_WALK_CONTINUE);
}

void
pcieadm_find_dip(pcieadm_t *pcip, const char *device)
{
	pcieadm_di_walk_t walk;

	/*
	 * If someone specifies /devices, just skip over it.
	 */
	pcip->pia_devstr = device;
	if (strncmp("/devices", device, strlen("/devices")) == 0) {
		pcip->pia_devstr += strlen("/devices");
	}

	pcip->pia_devi = DI_NODE_NIL;
	walk.pdw_arg = pcip;
	walk.pdw_func = pcieadm_find_dip_cb;
	pcieadm_di_walk(pcip, &walk);

	if (pcip->pia_devi == DI_NODE_NIL) {
		errx(EXIT_FAILURE, "failed to find device node %s", device);
	}

	pcip->pia_nexus = DI_NODE_NIL;
	pcieadm_find_nexus(pcip);
	if (pcip->pia_nexus == DI_NODE_NIL) {
		errx(EXIT_FAILURE, "failed to find nexus for %s", device);
	}
}

typedef struct pcieadm_cfgspace_file {
	int pcfi_fd;
} pcieadm_cfgspace_file_t;

static boolean_t
pcieadm_pop_cfgspace_file(uint32_t off, uint8_t len, void *buf, void *arg)
{
	uint32_t bufoff = 0;
	pcieadm_cfgspace_file_t *pcfi = arg;

	while (len > 0) {
		ssize_t ret = pread(pcfi->pcfi_fd, buf + bufoff, len, off);
		if (ret < 0) {
			err(EXIT_FAILURE, "failed to read %u bytes at %"
			    PRIu32, len, off);
		} else if (ret == 0) {
			warnx("hit unexpected EOF reading cfgspace from file "
			    "at offest %" PRIu32 ", still wanted to read %u "
			    "bytes", off, len);
			return (B_FALSE);
		} else {
			len -= ret;
			off += ret;
			bufoff += ret;
		}

	}

	return (B_TRUE);
}

static noreturn boolean_t
pcieadm_pop_bar_notsup(uint8_t bar, uint8_t len, uint64_t off, void *buf,
    void *arg, boolean_t write)
{
	errx(EXIT_FAILURE, "encountered unsupported request to %s %u bytes "
	    "from BAR %u at offset %" PRIx64, write ? "write" : "read", len,
	    bar, off);
}

static const pcieadm_ops_t pcieadm_file_ops = {
	.pop_cfg = pcieadm_pop_cfgspace_file,
	.pop_bar = pcieadm_pop_bar_notsup
};

void
pcieadm_init_ops_file(pcieadm_t *pcip, const char *path,
    const pcieadm_ops_t **opsp, void **arg)
{
	int fd;
	struct stat st;
	pcieadm_cfgspace_file_t *pcfi;

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) != 0) {
		err(EXIT_FAILURE, "failed to raise privileges");
	}

	if ((fd = open(path, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open input file %s", path);
	}

	if (fstat(fd, &st) != 0) {
		err(EXIT_FAILURE, "failed to get stat information for %s",
		    path);
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) != 0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	if (S_ISDIR(st.st_mode)) {
		errx(EXIT_FAILURE, "input file %s is a directory, unable "
		    "to read data", path);
	}

	if (S_ISLNK(st.st_mode)) {
		errx(EXIT_FAILURE, "input file %s is a symbolic link, unable "
		    "to read data", path);
	}

	if (S_ISDOOR(st.st_mode)) {
		errx(EXIT_FAILURE, "input file %s is a door, unable "
		    "to read data", path);
	}

	if (S_ISPORT(st.st_mode)) {
		errx(EXIT_FAILURE, "input file %s is an event port, unable "
		    "to read data", path);
	}

	/*
	 * Assume if we were given a FIFO, character/block device, socket, or
	 * something else that it's probably fine.
	 */
	pcfi = calloc(1, sizeof (*pcfi));
	if (pcfi == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for reading "
		    "cfgspace data from a file");
	}

	pcfi->pcfi_fd = fd;
	*arg = pcfi;
	*opsp = &pcieadm_file_ops;
}

void
pcieadm_fini_ops_file(void *arg)
{
	pcieadm_cfgspace_file_t *pcfi = arg;
	VERIFY0(close(pcfi->pcfi_fd));
	free(pcfi);
}

typedef struct pcieadm_cfgspace_kernel {
	pcieadm_t *pck_pci;
	int pck_fd;
	uint8_t pck_bus;
	uint8_t pck_dev;
	uint8_t pck_func;
} pcieadm_cfgspace_kernel_t;

static boolean_t
pcieadm_pop_kernel_common(uint8_t ptb, uint8_t len, uint64_t off, void *buf,
    void *arg, boolean_t write)
{
	pcieadm_cfgspace_kernel_t *pck = arg;
	pcieadm_t *pcip = pck->pck_pci;
	pcitool_reg_t pci_reg;

	bzero(&pci_reg, sizeof (pci_reg));
	pci_reg.user_version = PCITOOL_VERSION;
	pci_reg.bus_no = pck->pck_bus;
	pci_reg.dev_no = pck->pck_dev;
	pci_reg.func_no = pck->pck_func;
	pci_reg.barnum = ptb;
	pci_reg.offset = off;
	pci_reg.acc_attr = PCITOOL_ACC_ATTR_ENDN_LTL;

	switch (len) {
	case 1:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_1;
		break;
	case 2:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_2;
		break;
	case 4:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_4;
		break;
	case 8:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_8;
		break;
	default:
		errx(EXIT_FAILURE, "asked to read invalid size from kernel: %u",
		    len);
	}

	if (write) {
		switch (len) {
		case 1:
			pci_reg.data = *(uint8_t *)buf;
			break;
		case 2:
			pci_reg.data = *(uint16_t *)buf;
			break;
		case 4:
			pci_reg.data = *(uint32_t *)buf;
			break;
		case 8:
			pci_reg.data = *(uint64_t *)buf;
			break;
		}
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) != 0) {
		err(EXIT_FAILURE, "failed to raise privileges");
	}

	int cmd = write ? PCITOOL_DEVICE_SET_REG : PCITOOL_DEVICE_GET_REG;
	if (ioctl(pck->pck_fd, cmd, &pci_reg) != 0) {
		err(EXIT_FAILURE, "failed to read device offset 0x%" PRIx64
		    ": 0x%x", off, pci_reg.status);
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) != 0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	if (!write) {
		switch (len) {
		case 1:
			*(uint8_t *)buf = (uint8_t)pci_reg.data;
			break;
		case 2:
			*(uint16_t *)buf = (uint16_t)pci_reg.data;
			break;
		case 4:
			*(uint32_t *)buf = (uint32_t)pci_reg.data;
			break;
		case 8:
			*(uint64_t *)buf = (uint64_t)pci_reg.data;
			break;
		}
	}

	return (B_TRUE);

}

static boolean_t
pcieadm_pop_cfgspace_kernel(uint32_t off, uint8_t len, void *buf, void *arg)
{
	return (pcieadm_pop_kernel_common(PCITOOL_CONFIG, len, off, buf, arg,
	    B_FALSE));
}


static boolean_t
pcieadm_pop_bar_kernel(uint8_t bar, uint8_t len, uint64_t off, void *buf,
    void *arg, boolean_t write)
{
	if (bar >= PCI_BASE_NUM) {
		errx(EXIT_FAILURE, "requested to read %u bytes at 0x%" PRIx64
		    " from non-existent BAR %u", len, off, bar);
	}

	/*
	 * The ioctl interface uses 0 for configuration space and so the ioctl
	 * number is the bar plus one.
	 */
	return (pcieadm_pop_kernel_common(bar + 1, len, off, buf, arg, write));
}

static const pcieadm_ops_t pcieadm_kernel_ops = {
	.pop_cfg = pcieadm_pop_cfgspace_kernel,
	.pop_bar = pcieadm_pop_bar_kernel
};

void
pcieadm_init_ops_kernel(pcieadm_t *pcip, const pcieadm_ops_t **opsp, void **arg)
{
	char *nexus_base;
	char nexus_reg[PATH_MAX];
	int fd, nregs, *regs;
	pcieadm_cfgspace_kernel_t *pck;

	if ((nexus_base = di_devfs_path(pcip->pia_nexus)) == NULL) {
		err(EXIT_FAILURE, "failed to get path to nexus node");
	}

	if (snprintf(nexus_reg, sizeof (nexus_reg), "/devices%s:reg",
	    nexus_base) >= sizeof (nexus_reg)) {
		errx(EXIT_FAILURE, "failed to construct nexus path, path "
		    "overflow");
	}
	free(nexus_base);

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_eff) != 0) {
		err(EXIT_FAILURE, "failed to raise privileges");
	}

	if ((fd = open(nexus_reg, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", nexus_reg);
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcip->pia_priv_min) != 0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	nregs = di_prop_lookup_ints(DDI_DEV_T_ANY, pcip->pia_devi, "reg",
	    &regs);
	if (nregs <= 0) {
		errx(EXIT_FAILURE, "failed to lookup regs array for %s",
		    pcip->pia_devstr);
	}

	pck = calloc(1, sizeof (pcieadm_cfgspace_kernel_t));
	if (pck == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for reading "
		    "kernel cfgspace data");
	}

	pck->pck_pci = pcip;
	pck->pck_fd = fd;
	pck->pck_bus = PCI_REG_BUS_G(regs[0]);
	pck->pck_dev = PCI_REG_DEV_G(regs[0]);
	pck->pck_func = PCI_REG_FUNC_G(regs[0]);

	*opsp = &pcieadm_kernel_ops;
	*arg = pck;
}

void
pcieadm_fini_ops_kernel(void *arg)
{
	pcieadm_cfgspace_kernel_t *pck = arg;

	VERIFY0(close(pck->pck_fd));
	free(pck);
}

void
pcieadm_walk_usage(const pcieadm_cmdtab_t *tab, FILE *f)
{
	for (; tab->pct_name != NULL; tab++) {
		tab->pct_use(f);
	}
}

static void
pcieadm_usage(const pcieadm_cmdtab_t *tab, const char *format, ...)
{
	if (format != NULL) {
		va_list ap;

		va_start(ap, format);
		vwarnx(format, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "usage:  %s <subcommand> <args> ...\n\n",
	    pcieadm_progname);
	if (tab == NULL)
		return;
	pcieadm_walk_usage(tab, stderr);
}

int
pcieadm_walk_tab(pcieadm_t *pcip, const pcieadm_cmdtab_t *tab, int argc,
    char *argv[])
{
	uint32_t cmd;

	if (argc == 0) {
		pcieadm_usage(tab, "missing required sub-command");
		return (EXIT_FAILURE);
	}

	for (cmd = 0; tab[cmd].pct_name != NULL; cmd++) {
		if (strcmp(argv[0], tab[cmd].pct_name) == 0) {
			break;
		}
	}

	if (tab[cmd].pct_name == NULL) {
		pcieadm_usage(tab, "unknown subcommand %s", argv[0]);
		return (EXIT_USAGE);
	}

	argc--;
	argv++;
	optind = 0;
	pcieadm.pia_cmdtab = &tab[cmd];

	return (tab[cmd].pct_func(pcip, argc, argv));

}

static const pcieadm_cmdtab_t pcieadm_cmds[] = {
	{ "bar", pcieadm_bar, pcieadm_bar_usage },
	{ "show-cfgspace", pcieadm_show_cfgspace, pcieadm_show_cfgspace_usage },
	{ "save-cfgspace", pcieadm_save_cfgspace, pcieadm_save_cfgspace_usage },
	{ "show-devs", pcieadm_show_devs, pcieadm_show_devs_usage },
	{ NULL }
};

int
main(int argc, char *argv[])
{
	pcieadm_progname = basename(argv[0]);

	if (argc < 2) {
		pcieadm_usage(pcieadm_cmds, "missing required sub-command");
		exit(EXIT_USAGE);
	}

	argc--;
	argv++;

	/*
	 * Set up common things that all of pcieadm needs before dispatching to
	 * a specific sub-command.
	 */
	pcieadm.pia_pcidb = pcidb_open(PCIDB_VERSION);
	if (pcieadm.pia_pcidb == NULL) {
		err(EXIT_FAILURE, "failed to open PCI ID database");
	}

	/*
	 * Set up privileges now that we have already opened our core libraries.
	 * We first set up the minimum actual privilege set that we use while
	 * running. We next set up a second privilege set that has additional
	 * privileges that are intersected with the users actual privileges and
	 * are appended to by the underlying command backends.
	 */
	if ((pcieadm.pia_priv_init = priv_allocset()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate privilege set");
	}

	if (getppriv(PRIV_EFFECTIVE, pcieadm.pia_priv_init) != 0) {
		err(EXIT_FAILURE, "failed to get current privileges");
	}

	if ((pcieadm.pia_priv_min = priv_allocset()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate privilege set");
	}

	if ((pcieadm.pia_priv_eff = priv_allocset()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate privilege set");
	}

	/*
	 * Note, PRIV_FILE_READ is not removed from the basic set so that way we
	 * can still open libraries that are required due to lazy loading.
	 */
	priv_basicset(pcieadm.pia_priv_min);
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_FILE_LINK_ANY));
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_PROC_INFO));
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_PROC_SESSION));
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_PROC_FORK));
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_NET_ACCESS));
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_FILE_WRITE));
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_PROC_EXEC));
	VERIFY0(priv_delset(pcieadm.pia_priv_min, PRIV_PROC_EXEC));

	priv_copyset(pcieadm.pia_priv_min, pcieadm.pia_priv_eff);
	priv_intersect(pcieadm.pia_priv_init, pcieadm.pia_priv_eff);

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pcieadm.pia_priv_min) != 0) {
		err(EXIT_FAILURE, "failed to reduce privileges");
	}

	return (pcieadm_walk_tab(&pcieadm, pcieadm_cmds, argc, argv));
}
