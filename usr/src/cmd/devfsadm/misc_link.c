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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/zone.h>
#include <sys/zcons.h>
#include <sys/cpuid_drv.h>

static int display(di_minor_t minor, di_node_t node);
static int parallel(di_minor_t minor, di_node_t node);
static int node_slash_minor(di_minor_t minor, di_node_t node);
static int driver_minor(di_minor_t minor, di_node_t node);
static int node_name(di_minor_t minor, di_node_t node);
static int minor_name(di_minor_t minor, di_node_t node);
static int wifi_minor_name(di_minor_t minor, di_node_t node);
static int conskbd(di_minor_t minor, di_node_t node);
static int consms(di_minor_t minor, di_node_t node);
static int power_button(di_minor_t minor, di_node_t node);
static int fc_port(di_minor_t minor, di_node_t node);
static int printer_create(di_minor_t minor, di_node_t node);
static int se_hdlc_create(di_minor_t minor, di_node_t node);
static int ppm(di_minor_t minor, di_node_t node);
static int gpio(di_minor_t minor, di_node_t node);
static int av_create(di_minor_t minor, di_node_t node);
static int tsalarm_create(di_minor_t minor, di_node_t node);
static int ntwdt_create(di_minor_t minor, di_node_t node);
static int zcons_create(di_minor_t minor, di_node_t node);
static int cpuid(di_minor_t minor, di_node_t node);
static int glvc(di_minor_t minor, di_node_t node);
static int ses_callback(di_minor_t minor, di_node_t node);
static int kmdrv_create(di_minor_t minor, di_node_t node);

static devfsadm_create_t misc_cbt[] = {
	{ "pseudo", "ddi_pseudo", "(^sad$)",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, node_slash_minor
	},
	{ "pseudo", "ddi_pseudo", "zsh",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, driver_minor
	},
	{ "network", "ddi_network", NULL,
	    TYPE_EXACT, ILEVEL_0, minor_name
	},
	{ "wifi", "ddi_network:wifi", NULL,
	    TYPE_EXACT, ILEVEL_0, wifi_minor_name
	},
	{ "display", "ddi_display", NULL,
	    TYPE_EXACT, ILEVEL_0, display
	},
	{ "parallel", "ddi_parallel", NULL,
	    TYPE_EXACT, ILEVEL_0, parallel
	},
	{ "enclosure", DDI_NT_SCSI_ENCLOSURE, NULL,
	    TYPE_EXACT, ILEVEL_0, ses_callback
	},
	{ "pseudo", "ddi_pseudo", "(^winlock$)|(^pm$)",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, node_name
	},
	{ "pseudo", "ddi_pseudo", "conskbd",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, conskbd
	},
	{ "pseudo", "ddi_pseudo", "consms",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, consms
	},
	{ "pseudo", "ddi_pseudo", "eventfd",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name
	},
	{ "pseudo", "ddi_pseudo", "signalfd",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name
	},
	{ "pseudo", "ddi_pseudo", "rsm",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name
	},
	{ "pseudo", "ddi_pseudo",
	    "(^lockstat$)|(^SUNW,rtvc$)|(^vol$)|(^log$)|(^sy$)|"
	    "(^ksyms$)|(^clone$)|(^tl$)|(^tnf$)|(^kstat$)|(^mdesc$)|(^eeprom$)|"
	    "(^ptsl$)|(^mm$)|(^wc$)|(^dump$)|(^cn$)|(^svvslo$)|(^ptm$)|"
	    "(^ptc$)|(^openeepr$)|(^poll$)|(^sysmsg$)|(^random$)|(^trapstat$)|"
	    "(^cryptoadm$)|(^crypto$)|(^pool$)|(^poolctl$)|(^bl$)|(^kmdb$)|"
	    "(^sysevent$)|(^kssl$)|(^physmem$)",
	    TYPE_EXACT | DRV_RE, ILEVEL_1, minor_name
	},
	{ "pseudo", "ddi_pseudo",
	    "(^ip$)|(^tcp$)|(^udp$)|(^icmp$)|"
	    "(^ip6$)|(^tcp6$)|(^udp6$)|(^icmp6$)|"
	    "(^rts$)|(^arp$)|(^ipsecah$)|(^ipsecesp$)|(^keysock$)|(^spdsock$)|"
	    "(^nca$)|(^rds$)|(^sdp$)|(^ipnet$)|(^dlpistub$)|(^bpf$)",
	    TYPE_EXACT | DRV_RE, ILEVEL_1, minor_name
	},
	{ "pseudo", "ddi_pseudo", "ipd",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name
	},
	{ "pseudo", "ddi_pseudo",
	    "(^ipf$)|(^ipnat$)|(^ipstate$)|(^ipauth$)|"
	    "(^ipsync$)|(^ipscan$)|(^iplookup$)",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, minor_name,
	},
	{ "pseudo", "ddi_pseudo", "dld",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, node_name
	},
	{ "pseudo", "ddi_pseudo",
	    "(^kdmouse$)|(^rootprop$)",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, node_name
	},
	{ "pseudo", "ddi_pseudo", "timerfd",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name
	},
	{ "pseudo", "ddi_pseudo", "tod",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, node_name
	},
	{ "pseudo", "ddi_pseudo", "envctrl(two)?",
	    TYPE_EXACT | DRV_RE, ILEVEL_1, minor_name,
	},
	{ "pseudo", "ddi_pseudo", "fcode",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, minor_name,
	},
	{ "power_button", "ddi_power_button", NULL,
	    TYPE_EXACT, ILEVEL_0, power_button,
	},
	{ "FC port", "ddi_ctl:devctl", "fp",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, fc_port
	},
	{ "printer", "ddi_printer", NULL,
	    TYPE_EXACT, ILEVEL_0, printer_create
	},
	{ "pseudo", "ddi_pseudo", "se",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, se_hdlc_create
	},
	{ "ppm",  "ddi_ppm", NULL,
	    TYPE_EXACT, ILEVEL_0, ppm
	},
	{ "pseudo", "ddi_pseudo", "gpio_87317",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, gpio
	},
	{ "pseudo", "ddi_pseudo", "sckmdrv",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, kmdrv_create,
	},
	{ "pseudo", "ddi_pseudo", "oplkmdrv",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, kmdrv_create,
	},
	{ "av", "^ddi_av:(isoch|async)$", NULL,
	    TYPE_RE, ILEVEL_0, av_create,
	},
	{ "pseudo", "ddi_pseudo", "tsalarm",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, tsalarm_create,
	},
	{ "pseudo", "ddi_pseudo", "ntwdt",
	    TYPE_EXACT | DRV_RE, ILEVEL_0, ntwdt_create,
	},
	{ "pseudo", "ddi_pseudo", "daplt",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name
	},
	{ "pseudo", "ddi_pseudo", "zcons",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, zcons_create,
	},
	{ "pseudo", "ddi_pseudo", CPUID_DRIVER_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, cpuid,
	},
	{ "pseudo", "ddi_pseudo", "glvc",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, glvc,
	},
	{ "pseudo", "ddi_pseudo", "dm2s",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name,
	},
	{ "pseudo", "ddi_pseudo", "nsmb",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, minor_name,
	},
	{ "pseudo", "ddi_pseudo", "mem_cache",
	    TYPE_EXACT | DRV_RE, ILEVEL_1, minor_name,
	},
	{ "pseudo", "ddi_pseudo", "fm",
	    TYPE_EXACT | DRV_RE, ILEVEL_1, minor_name,
	},
	{ "pseudo", "ddi_pseudo", "smbsrv",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, minor_name,
	},
	{ "pseudo", "ddi_pseudo", "tpm",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, minor_name
	},
};

DEVFSADM_CREATE_INIT_V0(misc_cbt);

static devfsadm_remove_t misc_remove_cbt[] = {
	{ "pseudo", "^profile$",
	    RM_PRE | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^rsm$",
	    RM_PRE | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "printer", "^printers/[0-9]+$",
	    RM_PRE | RM_HOT | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "av", "^av/[0-9]+/(async|isoch)$",
	    RM_PRE | RM_HOT | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^daplt$",
	    RM_PRE | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^zcons/" ZONENAME_REGEXP "/(" ZCONS_MASTER_NAME "|"
		ZCONS_SLAVE_NAME ")$",
	    RM_PRE | RM_HOT | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^" CPUID_SELF_NAME "$", RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "enclosure", "^es/ses[0-9]+$", RM_POST,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^pfil$",
	    RM_PRE | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^tpm$",
	    RM_PRE | RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^sctp|sctp6$",
	    RM_PRE | RM_ALWAYS, ILEVEL_0, devfsadm_rm_link
	}
};

/* Rules for gpio devices */
static devfsadm_enumerate_t gpio_rules[1] =
	{"^gpio([0-9]+)$", 1, MATCH_ALL};

DEVFSADM_REMOVE_INIT_V0(misc_remove_cbt);

/*
 * Handles minor node type "ddi_display".
 *
 * type=ddi_display fbs/\M0 fb\N0
 */
static int
display(di_minor_t minor, di_node_t node)
{
	char l_path[PATH_MAX + 1], contents[PATH_MAX + 1], *buf;
	devfsadm_enumerate_t rules[1] = {"^fb([0-9]+)$", 1, MATCH_ALL};
	char *mn = di_minor_name(minor);

	/* create fbs/\M0 primary link */
	(void) strcpy(l_path, "fbs/");
	(void) strcat(l_path, mn);
	(void) devfsadm_mklink(l_path, node, minor, 0);

	/* create fb\N0 which links to fbs/\M0 */
	if (devfsadm_enumerate_int(l_path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}
	(void) strcpy(contents, l_path);
	(void) strcpy(l_path, "fb");
	(void) strcat(l_path, buf);
	free(buf);
	(void) devfsadm_secondary_link(l_path, contents, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Handles minor node type "ddi_parallel".
 * type=ddi_parallel;name=mcpp     mcpp\N0
 */
static int
parallel(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX + 1], *buf;
	devfsadm_enumerate_t rules[1] = {"mcpp([0-9]+)$", 1, MATCH_ALL};


	if (strcmp(di_node_name(node), "mcpp") != 0) {
		return (DEVFSADM_CONTINUE);
	}

	if (NULL == (buf = di_devfs_path(node))) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "%s:%s",
	    buf, di_minor_name(minor));

	di_devfs_path_free(buf);

	if (devfsadm_enumerate_int(path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}
	(void) snprintf(path, sizeof (path), "mcpp%s", buf);
	free(buf);

	(void) devfsadm_mklink(path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
ses_callback(di_minor_t minor, di_node_t node)
{
	char l_path[PATH_MAX];
	char *buf;
	char *devfspath;
	char p_path[PATH_MAX];
	devfsadm_enumerate_t re[] = {"^es$/^ses([0-9]+)$", 1, MATCH_ALL};

	/* find devices path -- need to free mem */
	if (NULL == (devfspath = di_devfs_path(node))) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(p_path, sizeof (p_path), "%s:%s", devfspath,
	    di_minor_name(minor));


	/* find next number to use; buf is an ascii number */
	if (devfsadm_enumerate_int(p_path, 0, &buf, re, 1)) {
		/* free memory */
		di_devfs_path_free(devfspath);
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(l_path, sizeof (l_path), "es/ses%s", buf);

	(void) devfsadm_mklink(l_path, node, minor, 0);
	/* free memory */
	free(buf);
	di_devfs_path_free(devfspath);
	return (DEVFSADM_CONTINUE);

}

static int
node_slash_minor(di_minor_t minor, di_node_t node)
{

	char path[PATH_MAX + 1];

	(void) strcpy(path, di_node_name(node));
	(void) strcat(path, "/");
	(void) strcat(path, di_minor_name(minor));
	(void) devfsadm_mklink(path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
driver_minor(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX + 1];

	(void) strcpy(path, di_driver_name(node));
	(void) strcat(path, di_minor_name(minor));
	(void) devfsadm_mklink(path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Handles links of the form:
 * type=ddi_pseudo;name=xyz  \D
 */
static int
node_name(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink(di_node_name(node), node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Handles links of the form:
 * type=ddi_pseudo;name=xyz  \M0
 */
static int
minor_name(di_minor_t minor, di_node_t node)
{
	char *mn = di_minor_name(minor);

	(void) devfsadm_mklink(mn, node, minor, 0);
	if (strcmp(mn, "icmp") == 0) {
		(void) devfsadm_mklink("rawip", node, minor, 0);
	}
	if (strcmp(mn, "icmp6") == 0) {
		(void) devfsadm_mklink("rawip6", node, minor, 0);
	}
	if (strcmp(mn, "ipf") == 0) {
		(void) devfsadm_mklink("ipl", node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);
}

/*
 * create links at /dev/wifi for wifi minor node
 */
static int
wifi_minor_name(di_minor_t minor, di_node_t node)
{
	char buf[256];
	char *mn = di_minor_name(minor);

	(void) snprintf(buf, sizeof (buf), "%s%s", "wifi/", mn);
	(void) devfsadm_mklink(buf, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
conskbd(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("kbd", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
consms(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("mouse", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
power_button(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("power_button", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
fc_port(di_minor_t minor, di_node_t node)
{
	devfsadm_enumerate_t rules[1] = {"fc/fp([0-9]+)$", 1, MATCH_ALL};
	char *buf, path[PATH_MAX + 1];
	char *ptr;

	if (NULL == (ptr = di_devfs_path(node))) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(path, ptr);
	(void) strcat(path, ":");
	(void) strcat(path, di_minor_name(minor));

	di_devfs_path_free(ptr);

	if (devfsadm_enumerate_int(path, 0, &buf, rules, 1) != 0) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(path, "fc/fp");
	(void) strcat(path, buf);
	free(buf);

	(void) devfsadm_mklink(path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Handles:
 *	minor node type "ddi_printer".
 * 	rules of the form: type=ddi_printer;name=bpp  \M0
 */
static int
printer_create(di_minor_t minor, di_node_t node)
{
	char *mn;
	char path[PATH_MAX + 1], *buf;
	devfsadm_enumerate_t rules[1] = {"^printers$/^([0-9]+)$", 1, MATCH_ALL};

	mn = di_minor_name(minor);

	if (strcmp(di_driver_name(node), "bpp") == 0) {
		(void) devfsadm_mklink(mn, node, minor, 0);
	}

	if (NULL == (buf = di_devfs_path(node))) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "%s:%s", buf, mn);
	di_devfs_path_free(buf);

	if (devfsadm_enumerate_int(path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "printers/%s", buf);
	free(buf);

	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

/*
 * Handles links of the form:
 * type=ddi_pseudo;name=se;minor2=hdlc	se_hdlc\N0
 * type=ddi_pseudo;name=serial;minor2=hdlc	se_hdlc\N0
 */
static int
se_hdlc_create(di_minor_t minor, di_node_t node)
{
	devfsadm_enumerate_t rules[1] = {"^se_hdlc([0-9]+)$", 1, MATCH_ALL};
	char *buf, path[PATH_MAX + 1];
	char *ptr;
	char *mn;

	mn = di_minor_name(minor);

	/* minor node should be of the form: "?,hdlc" */
	if (strcmp(mn + 1, ",hdlc") != 0) {
		return (DEVFSADM_CONTINUE);
	}

	if (NULL == (ptr = di_devfs_path(node))) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(path, ptr);
	(void) strcat(path, ":");
	(void) strcat(path, mn);

	di_devfs_path_free(ptr);

	if (devfsadm_enumerate_int(path, 0, &buf, rules, 1) != 0) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(path, "se_hdlc");
	(void) strcat(path, buf);
	free(buf);

	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
gpio(di_minor_t minor, di_node_t node)
{
	char l_path[PATH_MAX], p_path[PATH_MAX], *buf, *devfspath;
	char *minor_nm, *drvr_nm;


	minor_nm = di_minor_name(minor);
	drvr_nm = di_driver_name(node);
	if ((minor_nm == NULL) || (drvr_nm == NULL)) {
		return (DEVFSADM_CONTINUE);
	}

	devfspath = di_devfs_path(node);

	(void) strcpy(p_path, devfspath);
	(void) strcat(p_path, ":");
	(void) strcat(p_path, minor_nm);
	di_devfs_path_free(devfspath);

	/* build the physical path from the components */
	if (devfsadm_enumerate_int(p_path, 0, &buf, gpio_rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(l_path, sizeof (l_path), "%s%s", "gpio", buf);

	free(buf);

	(void) devfsadm_mklink(l_path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

/*
 * Creates /dev/ppm nodes for Platform Specific PM module
 */
static int
ppm(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("ppm", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Handles:
 *	/dev/av/[0-9]+/(async|isoch)
 */
static int
av_create(di_minor_t minor, di_node_t node)
{
	devfsadm_enumerate_t rules[1] = {"^av$/^([0-9]+)$", 1, MATCH_ADDR};
	char	*minor_str;
	char	path[PATH_MAX + 1];
	char	*buf;

	if ((buf = di_devfs_path(node)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	minor_str = di_minor_name(minor);
	(void) snprintf(path, sizeof (path), "%s:%s", buf, minor_str);
	di_devfs_path_free(buf);

	if (devfsadm_enumerate_int(path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "av/%s/%s", buf, minor_str);
	free(buf);

	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

/*
 * Creates /dev/lom and /dev/tsalarm:ctl for tsalarm node
 */
static int
tsalarm_create(di_minor_t minor, di_node_t node)
{
	char buf[PATH_MAX + 1];
	char *mn = di_minor_name(minor);

	(void) snprintf(buf, sizeof (buf), "%s%s", di_node_name(node), ":ctl");

	(void) devfsadm_mklink(mn, node, minor, 0);
	(void) devfsadm_mklink(buf, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

/*
 * Creates /dev/ntwdt for ntwdt node
 */
static int
ntwdt_create(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("ntwdt", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
zcons_create(di_minor_t minor, di_node_t node)
{
	char	*minor_str;
	char	*zonename;
	char	path[MAXPATHLEN];

	minor_str = di_minor_name(minor);

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "zonename",
	    &zonename) == -1) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "zcons/%s/%s", zonename,
	    minor_str);
	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

/*
 *	/dev/cpu/self/cpuid 	->	/devices/pseudo/cpuid@0:self
 */
static int
cpuid(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink(CPUID_SELF_NAME, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * For device
 *      /dev/spfma -> /devices/virtual-devices/fma@5:glvc
 */
static int
glvc(di_minor_t minor, di_node_t node)
{
	char node_name[MAXNAMELEN + 1];

	(void) strcpy(node_name, di_node_name(node));

	if (strncmp(node_name, "fma", 3) == 0) {
		/* Only one fma channel */
		(void) devfsadm_mklink("spfma", node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);
}

/*
 * Handles links of the form:
 * type=ddi_pseudo;name=sckmdrv		kmdrv\M0
 * type=ddi_pseudo;name=oplkmdrv	kmdrv\M0
 */
static int
kmdrv_create(di_minor_t minor, di_node_t node)
{

	(void) devfsadm_mklink("kmdrv", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}
