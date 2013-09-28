/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sac.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <devfsadm.h>
#include <syslog.h>

/*
 * sacadm output parsing
 */
#define	PMTAB_MAXLINE		512
#define	PMTAB_SEPR		':'
#define	PMTAB_DEVNAME_FIELD	7	/* field containing /dev/term/n */
#define	DIALOUT_SUFFIX		",cu"
#define	DEVNAME_SEPR		'/'
#define	MN_SEPR			','
#define	MN_NULLCHAR		'\0'

/*
 * sacadm/pmadm exit codes (see /usr/include/sac.h)
 */
static char *sacerrs[] = {
	"UNKNOWN", "Unknown exit code",
	"E_BADARGS", "Invalid arguments",
	"E_NOPRIV", "Not privileged",
	"E_SAFERR", "SAF error",
	"E_SYSERR",  "System error",
	"E_NOEXIST", "Entry does not exist",
	"E_DUP", "Entry already exists",
	"E_PMRUN", "Port monitor already running",
	"E_PMNOTRUN", "Port monitor not running",
	"E_RECOVER", "In recovery",
	"E_SACNOTRUN", "SAC daemon not running",
};

#define	SAC_EXITVAL(x)		((x) >> 8)
#define	SAC_EID(x)	\
	(sacerrs[((uint_t)(x) > E_SACNOTRUN ? 0 : ((x)<<1))])
#define	SAC_EMSG(x) \
	(sacerrs[((uint_t)(x) > E_SACNOTRUN ? 1 : (((x)<<1) + 1))])



/*
 * create port monitors for each group of PM_GRPSZ port devices.
 */
#define	PM_GRPSZ		64

/*
 * compute port monitor # and base index
 */
#define	PM_NUM(p)	((p) / PM_GRPSZ)
#define	PM_SLOT(p)	(PM_NUM(p) * PM_GRPSZ)


/*
 * default maxports value
 * override by setting SUNW_port_link.maxports in default/devfsadm
 */
#define	MAXPORTS_DEFAULT	2048

/*
 * command line buffer size for sacadm
 */
#define	CMDLEN			1024

struct pm_alloc {
	uint_t	flags;
	char	*pm_tag;
};

/* port monitor entry flags */
#define	PM_HAS_ENTRY	0x1		/* pm entry for this port */
#define	HAS_PORT_DEVICE	0x2		/* device exists */
#define	PORT_REMOVED	0x4		/* dangling port */
#define	HAS_PORT_MON	0x8		/* port monitor active */
#define	PM_NEEDED	0x10		/* port monitor needed */

static int maxports;
static struct pm_alloc *pma;
static char *modname = "SUNW_port_link";

/*
 * devfsadm_print message id
 */
#define	PORT_MID	"SUNW_port_link"

/*
 * enumeration regular expressions, port and onboard port devices
 * On x86, /dev/term|cua/[a..z] namespace is split into 2:
 * a-d are assigned based on minor name. e-z are
 * assigned via enumeration.
 */
static devfsadm_enumerate_t port_rules[] =
	{"^(term|cua)$/^([0-9]+)$", 1, MATCH_MINOR, "1"};

#ifdef __i386
static devfsadm_enumerate_t obport_rules[] =
	{"^(term|cua)$/^([e-z])$", 1, MATCH_MINOR, "1"};
static char start_id[] = "e";
#else
static devfsadm_enumerate_t obport_rules[] =
	{"^(term|cua)$/^([a-z])$", 1, MATCH_MINOR, "1"};
static char start_id[] = "a";
#endif

static int serial_port_create(di_minor_t minor, di_node_t node);
static int onbrd_port_create(di_minor_t minor, di_node_t node);
static int dialout_create(di_minor_t minor, di_node_t node);
static int onbrd_dialout_create(di_minor_t minor, di_node_t node);
static int rsc_port_create(di_minor_t minor, di_node_t node);
static int lom_port_create(di_minor_t minor, di_node_t node);
static void rm_dangling_port(char *devname);
static void update_sacadm_db(void);
static int parse_portno(char *dname);
static int is_dialout(char *dname);
static int load_ttymondb(void);
static void remove_pm_entry(char *pmtag, int port);
static void add_pm_entry(int port);
static void delete_port_monitor(int port);
static void add_port_monitor(int port);
static int execute(const char *s);
static char *pmtab_parse_portname(char *cmdbuf);
static void *pma_alloc(void);
static void pma_free(void);
extern char *defread(char *varname);
extern int defopen(char *fname);

/*
 * devfs create callback register
 */
static devfsadm_create_t ports_cbt[] = {
	{"pseudo", "ddi_pseudo", "su",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, rsc_port_create},
	{"port", "ddi_serial:lomcon", "su",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, lom_port_create},
	{"port", "ddi_serial", NULL,
	    TYPE_EXACT, ILEVEL_0, serial_port_create},
	{"port", "ddi_serial:mb", NULL,
	    TYPE_EXACT, ILEVEL_0, onbrd_port_create},
	{"port", "ddi_serial:dialout", NULL,
	    TYPE_EXACT, ILEVEL_0, dialout_create},
	{"port", "ddi_serial:dialout,mb", NULL,
	    TYPE_EXACT, ILEVEL_0, onbrd_dialout_create},
};
DEVFSADM_CREATE_INIT_V0(ports_cbt);

/*
 * devfs cleanup register
 * no cleanup rules for PCMCIA port devices
 */
static devfsadm_remove_t ports_remove_cbt[] = {
	{"port", "^term/[0-9]+$", RM_PRE | RM_ALWAYS | RM_HOT, ILEVEL_0,
	    rm_dangling_port},
	{"port", "^cua/[0-9]+$", RM_PRE | RM_ALWAYS | RM_HOT, ILEVEL_0,
	    devfsadm_rm_all},
	{"port", "^(term|cua)/[a-z]$",
	    RM_PRE | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all},
};
DEVFSADM_REMOVE_INIT_V0(ports_remove_cbt);

int
minor_init()
{
	char *maxport_str;

	if (defopen("/etc/default/devfsadm") == 0) {
		maxport_str = defread("SUNW_port_link.maxports");
		if ((maxport_str == NULL) ||
		    (sscanf(maxport_str, "%d", &maxports) != 1)) {
			maxports = MAXPORTS_DEFAULT;
		}
		/* close defaults file */
		(void) defopen(NULL);
	} else {
		maxports = MAXPORTS_DEFAULT;
	}

	devfsadm_print(CHATTY_MID, "%s: maximum number of port devices (%d)\n",
	    modname, maxports);

	if (pma_alloc() == NULL)
		return (DEVFSADM_FAILURE);

	return (DEVFSADM_SUCCESS);
}

int
minor_fini()
{
	/*
	 * update the sacadm database only if we are updating
	 * this platform (no -r option)
	 */
	if (strcmp(devfsadm_root_path(), "/") == 0)
		update_sacadm_db();

	pma_free();

	return (DEVFSADM_SUCCESS);
}

/*
 * Called for all serial devices that are NOT onboard
 * Creates links of the form "/dev/term/[0..n]"
 * Schedules an update the sacadm (portmon).
 */
static int
serial_port_create(di_minor_t minor, di_node_t node)
{
	char l_path[MAXPATHLEN], p_path[MAXPATHLEN];
	char *devfspath, *buf, *minor_name;
	int port_num;

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_errprint("%s: di_devfs_path() failed\n", modname);
		return (DEVFSADM_CONTINUE);
	}

	if ((minor_name = di_minor_name(minor)) == NULL) {
		devfsadm_errprint("%s: NULL minor name\n\t%s\n", modname,
		    devfspath);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * verify dialout ports do not come in on this nodetype
	 */
	if (is_dialout(minor_name)) {
		devfsadm_errprint("%s: dialout device\n\t%s:%s\n",
		    modname, devfspath, minor_name);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * add the minor name to the physical path so we can
	 * enum the port# and create the link.
	 */
	(void) strcpy(p_path, devfspath);
	(void) strcat(p_path, ":");
	(void) strcat(p_path, minor_name);
	di_devfs_path_free(devfspath);

	if (devfsadm_enumerate_int(p_path, 0, &buf, port_rules, 1)) {
		devfsadm_errprint("%s:serial_port_create:"
		    " enumerate_int() failed\n\t%s\n",
		    modname, p_path);
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(l_path, "term/");
	(void) strcat(l_path, buf);
	(void) devfsadm_mklink(l_path, node, minor, 0);

	/*
	 * This is probably a USB serial port coming into the system
	 * because someone just plugged one in.  Log an indication of
	 * this to syslog just in case someone wants to know what the
	 * name of the new serial device is ..
	 */
	(void) syslog(LOG_INFO, "serial device /dev/%s present", l_path);

	/*
	 * update the portmon database if this port falls within
	 * the valid range of ports.
	 */
	if ((port_num = parse_portno(buf)) != -1) {
		pma[port_num].flags |= HAS_PORT_DEVICE;
	}

	free(buf);
	return (DEVFSADM_CONTINUE);
}

/*
 * Called for all dialout devices that are NOT onboard
 * Creates links of the form "/dev/cua/[0..n]"
 */
static int
dialout_create(di_minor_t minor, di_node_t node)
{
	char l_path[MAXPATHLEN], p_path[MAXPATHLEN];
	char  *devfspath, *buf, *mn;

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_errprint("%s: di_devfs_path() failed\n", modname);
		return (DEVFSADM_CONTINUE);
	}

	if ((mn = di_minor_name(minor)) == NULL) {
		devfsadm_errprint("%s: NULL minorname\n\t%s\n",
		    modname, devfspath);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	if (!is_dialout(mn)) {
		devfsadm_errprint("%s: invalid minor name\n\t%s:%s\n",
		    modname, devfspath, mn);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(p_path, devfspath);
	(void) strcat(p_path, ":");
	(void) strcat(p_path, mn);
	di_devfs_path_free(devfspath);

	if (devfsadm_enumerate_int(p_path, 0, &buf, port_rules, 1)) {
		devfsadm_errprint("%s:dialout_create:"
		    " enumerate_int() failed\n\t%s\n",
		    modname, p_path);
		return (DEVFSADM_CONTINUE);
	}
	(void) strcpy(l_path, "cua/");
	(void) strcat(l_path, buf);

	/*
	 *  add the minor name to the physical path so we can create
	 *  the link.
	 */
	(void) devfsadm_mklink(l_path, node, minor, 0);

	free(buf);
	return (DEVFSADM_CONTINUE);
}

#ifdef __i386

static int
portcmp(char *devfs_path, char *phys_path)
{
	char *p1, *p2;
	int rv;

	p2 = NULL;

	p1 = strrchr(devfs_path, ':');
	if (p1 == NULL)
		return (1);

	p1 = strchr(p1, ',');
	if (p1)
		*p1 = '\0';

	p2 = strrchr(phys_path, ':');
	if (p2 == NULL) {
		rv = -1;
		goto out;
	}

	p2 = strchr(p2, ',');
	if (p2)
		*p2 = '\0';

	rv = strcmp(devfs_path, phys_path);

out:
	if (p1)
		*p1 = ',';
	if (p2)
		*p2 = ',';

	return (rv);
}

/*
 * If the minor name begins with [a-d] and the
 * links in /dev/term/<char> and /dev/cua/<char>
 * don't point at a different minor, then we can
 * create compatibility links for this minor.
 * Returns:
 *	port id if a compatibility link can be created.
 *	NULL otherwise
 */
static char *
check_compat_ports(di_node_t node, char *phys_path, char *minor)
{
	char portid = *minor;
	char port[PATH_MAX];
	char *devfs_path;

	if (portid < 'a' || portid >  'd')
		return (NULL);

	(void) snprintf(port, sizeof (port), "term/%c", portid);
	if (devfsadm_read_link(node, port, &devfs_path) == DEVFSADM_SUCCESS &&
	    portcmp(devfs_path, phys_path) != 0) {
		free(devfs_path);
		return (NULL);
	}

	free(devfs_path);

	(void) snprintf(port, sizeof (port), "cua/%c", portid);
	if (devfsadm_read_link(node, port, &devfs_path) == DEVFSADM_SUCCESS &&
	    portcmp(devfs_path, phys_path) != 0) {
		free(devfs_path);
		return (NULL);
	}

	free(devfs_path);

	/*
	 * Neither link exists or both links point at "phys_path"
	 * We can safely create compatibility links.
	 */
	port[0] = portid;
	port[1] = '\0';

	return (s_strdup(port));
}

#endif

/*
 * Called for all Onboard serial devices
 * Creates links of the form "/dev/term/[a..z]"
 */
static int
onbrd_port_create(di_minor_t minor, di_node_t node)
{
	char l_path[MAXPATHLEN], p_path[MAXPATHLEN];
	char  *devfspath, *buf, *minor_name;

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_errprint("%s: di_devfs_path() failed\n", modname);
		return (DEVFSADM_CONTINUE);
	}

	if ((minor_name = di_minor_name(minor)) == NULL) {
		devfsadm_errprint("%s: NULL minor name\n\t%s\n",
		    modname, devfspath);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * verify dialout ports do not come in on this nodetype
	 */
	if (is_dialout(minor_name)) {
		devfsadm_errprint("%s: dialout device\n\t%s:%s\n", modname,
		    devfspath, minor_name);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(p_path, devfspath);
	(void) strcat(p_path, ":");
	(void) strcat(p_path, minor_name);
	di_devfs_path_free(devfspath);


	buf = NULL;

#ifdef __i386
	buf = check_compat_ports(node, p_path, minor_name);
#endif

	/*
	 * devfsadm_enumerate_char_start() is a private interface for use by the
	 * ports module only
	 */
	if (!buf && devfsadm_enumerate_char_start(p_path, 0, &buf, obport_rules,
	    1, start_id)) {
		devfsadm_errprint("%s: devfsadm_enumerate_char_start() failed"
		    "\n\t%s\n", modname, p_path);
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(l_path, "term/");
	(void) strcat(l_path, buf);
	(void) devfsadm_mklink(l_path, node, minor, 0);
	free(buf);
	return (DEVFSADM_CONTINUE);
}

/*
 * Onboard dialout devices
 * Creates links of the form "/dev/cua/[a..z]"
 */
static int
onbrd_dialout_create(di_minor_t minor, di_node_t node)
{
	char l_path[MAXPATHLEN], p_path[MAXPATHLEN];
	char  *devfspath, *buf, *mn;

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_errprint("%s: di_devfs_path() failed\n", modname);
		return (DEVFSADM_CONTINUE);
	}

	if ((mn = di_minor_name(minor)) == NULL) {
		devfsadm_errprint("%s: NULL minor name\n\t%s\n",
		    modname, devfspath);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * verify this is a dialout port
	 */
	if (!is_dialout(mn)) {
		devfsadm_errprint("%s: not a dialout device\n\t%s:%s\n",
		    modname, devfspath, mn);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(p_path, devfspath);
	(void) strcat(p_path, ":");
	(void) strcat(p_path, mn);
	di_devfs_path_free(devfspath);

	buf = NULL;

#ifdef __i386
	buf = check_compat_ports(node, p_path, mn);
#endif

	/*
	 * devfsadm_enumerate_char_start() is a private interface
	 * for use by the ports module only.
	 */
	if (!buf && devfsadm_enumerate_char_start(p_path, 0, &buf, obport_rules,
	    1, start_id)) {
		devfsadm_errprint("%s: devfsadm_enumerate_char_start() failed"
		    "\n\t%s\n", modname, p_path);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * create the logical link
	 */
	(void) strcpy(l_path, "cua/");
	(void) strcat(l_path, buf);
	(void) devfsadm_mklink(l_path, node, minor, 0);
	free(buf);
	return (DEVFSADM_CONTINUE);
}


/*
 * Remote System Controller (RSC) serial ports
 * Creates links of the form "/dev/rsc-control" | "/dev/term/rsc-console".
 */
static int
rsc_port_create(di_minor_t minor, di_node_t node)
{
	char  *devfspath;
	char  *minor_name;


	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_errprint("%s: di_devfs_path() failed\n", modname);
		return (DEVFSADM_CONTINUE);
	}

	if ((minor_name = di_minor_name(minor)) == NULL) {
		devfsadm_errprint("%s: NULL minor name\n\t%s\n",
		    modname, devfspath);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * if this is the RSC console serial port (i.e. the minor name == ssp),
	 * create /dev/term/rsc-console link and then we are done with this
	 * node.
	 */
	if (strcmp(minor_name, "ssp") == 0) {
		(void) devfsadm_mklink("term/rsc-console", node, minor, 0);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_TERMINATE);

	/*
	 * else if this is the RSC control serial port (i.e. the minor name ==
	 * sspctl), create /dev/rsc-control link and then we are done with this
	 * node.
	 */
	} else if (strcmp(minor_name, "sspctl") == 0) {
		(void) devfsadm_mklink("rsc-control", node, minor, 0);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_TERMINATE);
	}

	/* This is not an RSC node, continue... */
	di_devfs_path_free(devfspath);
	return (DEVFSADM_CONTINUE);
}

/*
 * Lights Out Management (LOM) serial ports
 * Creates links of the form "/dev/term/lom-console".
 */
static int
lom_port_create(di_minor_t minor, di_node_t node)
{
	char  *devfspath;
	char  *minor_name;

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_errprint("%s: di_devfs_path() failed\n", modname);
		return (DEVFSADM_CONTINUE);
	}

	if ((minor_name = di_minor_name(minor)) == NULL) {
		devfsadm_errprint("%s: NULL minor name\n\t%s\n",
		    modname, devfspath);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * if this is the LOM console serial port (i.e. the minor
	 * name == lom-console ), create /dev/term/lom-console link and
	 * then we are done with this node.
	 */
	if (strcmp(minor_name, "lom-console") == 0) {
		(void) devfsadm_mklink("term/lom-console", node, minor, 0);
		di_devfs_path_free(devfspath);
		return (DEVFSADM_TERMINATE);
	}

	/* This is not a LOM node, continue... */
	di_devfs_path_free(devfspath);
	return (DEVFSADM_CONTINUE);
}


/*
 * Removes port entries that no longer have devices
 * backing them
 * Schedules an update the sacadm (portmon) database
 */
static void
rm_dangling_port(char *devname)
{
	char *portstr;
	int  portnum;

	devfsadm_print(PORT_MID, "%s:rm_stale_port: %s\n",
	    modname, devname);

	if ((portstr = strrchr(devname, (int)'/')) == NULL) {
		devfsadm_errprint("%s: invalid name: %s\n",
		    modname, devname);
		return;
	}
	portstr++;

	/*
	 * mark for removal from sacadm database
	 */
	if ((portnum = parse_portno(portstr)) != -1)
		pma[portnum].flags |= PORT_REMOVED;

	devfsadm_rm_all(devname);
}

/*
 * Algorithm is to step through ports; checking for unneeded PM entries
 * entries that should be there but are not.  Every PM_GRPSZ entries
 * check to see if there are any entries for the port monitor group;
 * if not, delete the group.
 */
static void
update_sacadm_db(void)
{
	int i;

	if (load_ttymondb() != DEVFSADM_SUCCESS)
		return;

	for (i = 0; i < maxports; i++) {
		/*
		 * if this port was removed and has a port
		 * monitor entry, remove the entry from the sacadm db
		 */
		if ((pma[i].flags & PORT_REMOVED) != 0) {
			if ((pma[i].flags & PM_HAS_ENTRY) != 0)
				remove_pm_entry(pma[i].pm_tag, i);
		}

		/*
		 * if this port is present and lacks a port monitor
		 * add an entry to the sacadm db
		 */
		if (pma[i].flags & HAS_PORT_DEVICE) {
			if (!(pma[i].flags & PM_HAS_ENTRY))
				add_pm_entry(i);
		}

		/*
		 * if this port has a pm entry, mark as needing
		 * a port monitor within this range of ports
		 */
		if ((pma[i].flags & PM_HAS_ENTRY))
			pma[PM_SLOT(i)].flags |= PM_NEEDED;

		/*
		 * continue for the range of ports per-portmon
		 */
		if (((i + 1) % PM_GRPSZ) != 0)
			continue;

		/*
		 * if there are no ports active on the range we have
		 * just completed, remove the port monitor entry if
		 * it exists
		 */
		if ((pma[PM_SLOT(i)].flags & (PM_NEEDED | HAS_PORT_MON)) ==
		    HAS_PORT_MON) {
			delete_port_monitor(i);
		}

	}

	/*
	 * cleanup remaining port monitor, if active
	 */
	if ((i % PM_GRPSZ != 0) &&
	    ((pma[PM_SLOT(i)].flags & (PM_NEEDED | HAS_PORT_MON)) ==
	    HAS_PORT_MON)) {
		delete_port_monitor(i);
	}
}

/*
 * Determine which port monitor entries already exist by invoking pmadm(1m)
 * to list all configured 'ttymon' port monitor entries.
 * Do not explicitly report errors from executing pmadm(1m) or sacadm(1m)
 * commands to remain compatible with the ports(1m) implementation.
 */
static int
load_ttymondb(void)
{
	char	cmdline[CMDLEN];
	char	cmdbuf[PMTAB_MAXLINE+1];
	int	sac_exitval;
	FILE	*fs_popen;
	char	*portname;	/* pointer to a tty name */
	int	portnum;
	char	*ptr;
	char	*error_msg = "%s: failed to load port monitor database\n";

	(void) strcpy(cmdline, "/usr/sbin/pmadm -L -t ttymon");
	fs_popen = popen(cmdline, "r");
	if (fs_popen == NULL) {
		devfsadm_print(VERBOSE_MID, error_msg, modname);
		return (DEVFSADM_FAILURE);
	}

	while (fgets(cmdbuf, PMTAB_MAXLINE, fs_popen) != NULL) {
		if ((portname = pmtab_parse_portname(cmdbuf)) == NULL) {
			devfsadm_print(VERBOSE_MID,
			    "load_ttymondb: failed to parse portname\n");
			devfsadm_print(VERBOSE_MID,
			    "load_ttymondb: buffer \"%s\"\n", cmdbuf);
			goto load_failed;
		}

		devfsadm_print(PORT_MID, "%s:load_ttymondb: port %s ",
		    modname, portname);

		/*
		 * skip onboard ports
		 * There is no reliable way to determine if we
		 * should start a port monitor on these lines.
		 */
		if ((portnum = parse_portno(portname)) == -1) {
			devfsadm_print(PORT_MID, "ignored\n");
			continue;
		}

		/*
		 * the first field of the pmadm output is
		 * the port monitor name for this entry
		 */
		if ((ptr = strchr(cmdbuf, PMTAB_SEPR)) == NULL) {
			devfsadm_print(VERBOSE_MID,
			    "load_ttymondb: no portmon tag\n");
			goto load_failed;
		}

		*ptr = MN_NULLCHAR;
		if ((pma[portnum].pm_tag = strdup(cmdbuf)) == NULL) {
			devfsadm_errprint("load_ttymondb: failed strdup\n");
			goto load_failed;
		}
		pma[portnum].flags |= PM_HAS_ENTRY;
		pma[PM_SLOT(portnum)].flags |= HAS_PORT_MON;
		devfsadm_print(PORT_MID, "present\n");
	}
	(void) pclose(fs_popen);
	return (DEVFSADM_SUCCESS);

load_failed:

	/*
	 * failed to load the port monitor database
	 */
	devfsadm_print(VERBOSE_MID, error_msg, modname);
	sac_exitval = SAC_EXITVAL(pclose(fs_popen));
	if (sac_exitval != 0) {
		devfsadm_print(VERBOSE_MID,
		    "pmadm: (%s) %s\n", SAC_EID(sac_exitval),
		    SAC_EMSG(sac_exitval));
	}
	return (DEVFSADM_FAILURE);
}

/*
 * add a port monitor entry for device /dev/term/"port"
 */
static void
add_pm_entry(int port)
{
	char cmdline[CMDLEN];
	int sac_exitval;

	add_port_monitor(port);
	(void) sprintf(cmdline,
	    "/usr/sbin/pmadm -a -p ttymon%d -s %d -i root"
	    " -v `/usr/sbin/ttyadm -V` -fux -y\"/dev/term/%d\""
	    " -m \"`/usr/sbin/ttyadm -d /dev/term/%d -s /usr/bin/login"
	    " -l 9600 -p \\\"login: \\\"`\"", PM_NUM(port), port, port, port);

	if (devfsadm_noupdate() == DEVFSADM_FALSE) {
		sac_exitval = execute(cmdline);
		if ((sac_exitval != 0) && (sac_exitval != E_SACNOTRUN)) {
			devfsadm_print(VERBOSE_MID,
			    "failed to add port monitor entry"
			    " for /dev/term/%d\n", port);
			devfsadm_print(VERBOSE_MID, "pmadm: (%s) %s\n",
			    SAC_EID(sac_exitval), SAC_EMSG(sac_exitval));
		}
	}
	pma[port].flags |= PM_HAS_ENTRY;
	devfsadm_print(VERBOSE_MID, "%s: /dev/term/%d added to sacadm\n",
	    modname, port);
}

static void
remove_pm_entry(char *pmtag, int port)
{

	char cmdline[CMDLEN];
	int sac_exitval;

	if (devfsadm_noupdate() == DEVFSADM_FALSE) {
		(void) snprintf(cmdline, sizeof (cmdline),
		    "/usr/sbin/pmadm -r -p %s -s %d", pmtag, port);
		sac_exitval = execute(cmdline);
		if ((sac_exitval != 0) && (sac_exitval != E_SACNOTRUN)) {
			devfsadm_print(VERBOSE_MID,
			    "failed to remove port monitor entry"
			    " for /dev/term/%d\n", port);
			devfsadm_print(VERBOSE_MID, "pmadm: (%s) %s\n",
			    SAC_EID(sac_exitval), SAC_EMSG(sac_exitval));
		}
	}
	pma[port].flags &= ~PM_HAS_ENTRY;
	devfsadm_print(VERBOSE_MID, "%s: /dev/term/%d removed from sacadm\n",
	    modname, port);
}


/*
 * delete_port_monitor()
 * Check for the existence of a port monitor for "port" and remove it if
 * one exists
 */
static void
delete_port_monitor(int port)
{
	char	cmdline[CMDLEN];
	int	sac_exitval;

	(void) sprintf(cmdline, "/usr/sbin/sacadm -L -p ttymon%d",
	    PM_NUM(port));
	sac_exitval = execute(cmdline);

	/* clear the PM tag and return if the port monitor is not active */
	if (sac_exitval == E_NOEXIST) {
		pma[PM_SLOT(port)].flags &= ~HAS_PORT_MON;
		return;
	}

	/* some other sacadm(1m) error, log and return */
	if (sac_exitval != 0) {
		devfsadm_print(VERBOSE_MID, "sacadm: (%s) %s\n",
		    SAC_EID(sac_exitval), SAC_EMSG(sac_exitval));
		return;
	}

	if (devfsadm_noupdate() == DEVFSADM_FALSE) {
		(void) sprintf(cmdline,
		    "/usr/sbin/sacadm -r -p ttymon%d", PM_NUM(port));
		if (sac_exitval = execute(cmdline)) {
			devfsadm_print(VERBOSE_MID,
			    "failed to remove port monitor ttymon%d\n",
			    PM_NUM(port));
			devfsadm_print(VERBOSE_MID, "sacadm: (%s) %s\n",
			    SAC_EID(sac_exitval), SAC_EMSG(sac_exitval));
		}
	}
	devfsadm_print(VERBOSE_MID, "%s: port monitor ttymon%d removed\n",
	    modname, PM_NUM(port));
	pma[PM_SLOT(port)].flags &= ~HAS_PORT_MON;
}

static void
add_port_monitor(int port)
{
	char cmdline[CMDLEN];
	int sac_exitval;

	if ((pma[PM_SLOT(port)].flags & HAS_PORT_MON) != 0) {
		return;
	}

	(void) sprintf(cmdline,
	    "/usr/sbin/sacadm -l -p ttymon%d", PM_NUM(port));
	sac_exitval = execute(cmdline);
	if (sac_exitval == E_NOEXIST) {
		(void) sprintf(cmdline,
		    "/usr/sbin/sacadm -a -n 2 -p ttymon%d -t ttymon"
		    " -c /usr/lib/saf/ttymon -v \"`/usr/sbin/ttyadm"
		    " -V`\" -y \"Ports %d-%d\"", PM_NUM(port), PM_SLOT(port),
		    PM_SLOT(port) + (PM_GRPSZ - 1));
		if (devfsadm_noupdate() == DEVFSADM_FALSE) {
			if (sac_exitval = execute(cmdline)) {
				devfsadm_print(VERBOSE_MID,
				    "failed to add port monitor ttymon%d\n",
				    PM_NUM(port));
				devfsadm_print(VERBOSE_MID, "sacadm: (%s) %s\n",
				    SAC_EID(sac_exitval),
				    SAC_EMSG(sac_exitval));
			}
		}
		devfsadm_print(VERBOSE_MID, "%s: port monitor ttymon%d added\n",
		    modname, PM_NUM(port));
	}
	pma[PM_SLOT(port)].flags |= HAS_PORT_MON;
}

/*
 * parse port number from string
 * returns port number if in range [0..maxports]
 */
static int
parse_portno(char *dname)
{
	int pn;

	if (sscanf(dname, "%d", &pn) != 1)
		return (-1);

	if ((pn < 0) || (pn > maxports)) {
		devfsadm_print(VERBOSE_MID,
		    "%s:parse_portno: %d not in range (0..%d)\n",
		    modname, pn, maxports);
		return (-1);
	}

	return (pn);
}


/*
 * fork and exec a command, waiting for the command to
 * complete and return it's status
 */
static int
execute(const char *s)
{
	int	status;
	int	fd;
	pid_t	pid;
	pid_t	w;

	/*
	 * fork a single threaded child proc to execute the
	 * sacadm command string
	 */
	devfsadm_print(PORT_MID, "%s: execute:\n\t%s\n", modname, s);
	if ((pid = fork1()) == 0) {
		(void) close(0);
		(void) close(1);
		(void) close(2);
		fd = open("/dev/null", O_RDWR);
		(void) dup(fd);
		(void) dup(fd);
		(void) execl("/sbin/sh", "sh", "-c", s, 0);
		/*
		 * return the sacadm exit status (see _exit(2))
		 */
		_exit(127);
	}

	/*
	 * wait for child process to terminate
	 */
	for (;;) {
		w = wait(&status);
		if (w == pid) {
			devfsadm_print(PORT_MID, "%s:exit status (%d)\n",
			    modname, SAC_EXITVAL(status));
			return (SAC_EXITVAL(status));
		}
		if (w == (pid_t)-1) {
			devfsadm_print(VERBOSE_MID, "%s: exec failed\n",
			    modname);
			return (-1);
		}
	}

	/* NOTREACHED */
}


/*
 * check if the minor name is suffixed with ",cu"
 */
static int
is_dialout(char *name)
{
	char *s_chr;

	if ((name == NULL) || (s_chr = strrchr(name, MN_SEPR)) == NULL)
		return (0);

	if (strcmp(s_chr, DIALOUT_SUFFIX) == 0) {
		return (1);
	} else {
		return (0);
	}
}


/*
 * Get the name of the port device from a pmtab entry.
 * Note the /dev/term/ part is taken off.
 */
static char *
pmtab_parse_portname(char *buffer)
{
	int i;
	char *bufp, *devnamep, *portnamep;

	/*
	 * position to the device name (field 8)
	 */
	bufp = strchr(buffer, PMTAB_SEPR);
	for (i = 0; i < PMTAB_DEVNAME_FIELD; i++) {
		if (bufp == NULL)
			return (NULL);
		bufp = strchr(++bufp, PMTAB_SEPR);
	}

	/* move past the ':' and locate the end of the devname */
	devnamep = bufp++;
	if ((bufp = strchr(bufp, PMTAB_SEPR)) == NULL)
		return (NULL);

	*bufp = MN_NULLCHAR;
	if ((portnamep = strrchr(devnamep, DEVNAME_SEPR)) == NULL) {
		*bufp = PMTAB_SEPR;
		return (NULL);
	}

	/* return with "buffer" chopped after the /dev/term entry */

	return (++portnamep);
}

/*
 * port monitor array mgmt
 */
static void *
pma_alloc(void)
{

	if (pma != NULL) {
		devfsadm_errprint("%s:pma_alloc:pma != NULL\n", modname);
		return (NULL);
	}

	if ((pma = calloc(maxports + 1, sizeof (*pma))) == NULL) {
		devfsadm_errprint("%s:pma_alloc:pma alloc failure\n", modname);
		return (NULL);
	}

	return ((void *)pma);
}

static void
pma_free(void)
{

	int i;

	if (pma == NULL)
		return;

	/*
	 * free any strings we had allocated
	 */
	for (i = 0; i <= maxports; i++) {
		if (pma[i].pm_tag != NULL)
			free(pma[i].pm_tag);
	}

	free(pma);
	pma = NULL;
}
