/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/bootprops.h>
#include <sys/salib.h>
#include "debug.h"
#include "multiboot.h"

extern void install_memlistptrs();
#define	dprintf	if (debug & D_BPROP) printf

struct pseudoprop {
	char *pp_name;
	void (*pp_func)();
} pp_list[] = {
	{ "memory_update", install_memlistptrs },
	{ NULL, NULL}
};

struct bootprop {
	struct bootprop *bp_next;
	char *bp_name;
	void *bp_val;
	int bp_len;
};

static struct bootprop *bp_list;

static int find_pseudo(char *);
static struct bootprop *find_prop(char *);
static struct bootprop *alloc_prop(char *);
static void set_propval(struct bootprop *, void *, int);
static void setup_rarp_props(struct sol_netinfo *);

/*
 *  Return the length of the "name"d property's value.
 */
/*ARGSUSED*/
int
bgetproplen(struct bootops *bop, char *name)
{
	struct bootprop *bp;

	dprintf("bgetproplen: name = %s\n", name);
	bp = find_prop(name);
	return (bp ? bp->bp_len : BOOT_FAILURE);
}

/*ARGSUSED*/
int
bgetprop(struct bootops *bop, char *name, void *value)
{
	struct bootprop *bp;

	dprintf("bgetprop: name = %s\n", name);
	if (find_pseudo(name) == BOOT_SUCCESS)
		return (BOOT_SUCCESS);

	bp = find_prop(name);
	if (!bp)
		return (BOOT_FAILURE);

	/* Found the property in question; return its value */
	(void) bcopy(bp->bp_val, value, bp->bp_len);
	return (BOOT_SUCCESS);
}

/*ARGSUSED*/
char *
bnextprop(struct bootops *bop, char *prev)
{
	struct bootprop *bp = find_prop(prev);

	if (bp == NULL || bp->bp_next == NULL)
		return (NULL);
	return (bp->bp_next->bp_name);
}

/*ARGSUSED*/
int
bsetprop(struct bootops *bop, char *name, void *value, int len)
{
	struct bootprop *bp;

	dprintf("bsetprop: name = %s, len = %d", name, len);
	bp = find_prop(name);
	if (bp == NULL)
		bp = alloc_prop(name);

	set_propval(bp, value, len);
	return (BOOT_SUCCESS);
}

int
find_pseudo(char *name)
{
	struct pseudoprop *pp = pp_list;

	while (pp->pp_name) {
		if (strcmp(name, pp->pp_name) == 0) {
			(*pp->pp_func)();
			dprintf("find_pseudo: prop = %s\n", name);
			return (BOOT_SUCCESS);
		}
		pp++;
	}
	return (BOOT_FAILURE);
}

struct bootprop *
find_prop(char *name)
{
	struct bootprop *bp = bp_list;

	if (name == NULL || *name == '\0')
		return (bp);

	while (bp) {
		if (strcmp(name, bp->bp_name) == 0)
			break;
		bp = bp->bp_next;
	}
	return (bp);
}

static struct bootprop *
alloc_prop(char *name)
{
	struct bootprop *bp = bkmem_zalloc(sizeof (*bp));

	dprintf("alloc_prop: name = %s\n", name);
	bp->bp_name = bkmem_alloc(strlen(name) + 1);
	(void) strcpy(bp->bp_name, name);
	bp->bp_next = bp_list;
	bp_list = bp;

	return (bp);
}

static void
set_propval(struct bootprop *bp, void *value, int len)
{
	dprintf("set_propval: name = %s\n", bp->bp_name);

	if (bp->bp_val)
		bkmem_free(bp->bp_val, bp->bp_len);
	bp->bp_len = len;
	bp->bp_val = bkmem_alloc(len);
	bcopy(value, bp->bp_val, len);
}

void
setup_bootprop(void)
{
	extern char bootprop[], bootargs[];
	extern char *bootprog;
	extern uint64_t ramdisk_start, ramdisk_end;
	extern multiboot_info_t *mbi;
	char *name, *val, *cp;
	int netboot = 0;
	int stdout_val = 0;		/* for a dummy property */

	if (verbosemode)
		printf("setup boot properties.\n");

	dprintf("process command line bootargs: %s\n", bootprop);
	cp = bootprop;
	while (cp && *cp) {
		name = strtok(cp, "=");
		val = strtok(NULL, "");
		if (val == NULL) {
			val = "true";
			cp = NULL;	/* terminate loop */
		} else if (*val != '\'' && *val != '\"') {
			if (*val == ',') {
				cp = val + 1;
				val = "";
			} else {
				cp = strtok(val, ",");
				cp = strtok(NULL, "");
			}
		} else {
			/* look for closing single or double quote */
			cp = val + 1;
			while (cp && *cp != *val)
				++cp;
			if (cp == NULL) {
				printf("missing %c in property %s.\n",
				    *val, name);
			} else {
				*cp++ = '\0';
				if (*cp == ',')
					cp++;
				else  if (*cp != '\0') {
					printf("syntax error in GRUB -B option:"
					    " ignore %s\n", cp);
					cp = NULL;	/* terminate */
				}
			}
			val++;
		}

		(void) bsetprop(NULL, name, val, strlen(val) + 1);
	}

	(void) bsetprop(NULL, "bootprog", bootprog, strlen(bootprog) + 1);
	(void) bsetprop(NULL, "boot-args", bootargs, strlen(bootargs) + 1);
	(void) bsetprop(NULL, "ramdisk_start", (char *)&ramdisk_start,
	    sizeof (ramdisk_start));
	(void) bsetprop(NULL, "ramdisk_end", (char *)&ramdisk_end,
	    sizeof (ramdisk_end));

	/* a bunch of fixed properties */
	(void) bsetprop(NULL, "mfg-name", "i86pc", sizeof ("i86pc"));
	(void) bsetprop(NULL, "impl-arch-name", "i86pc", sizeof ("i86pc"));

	/* figure out the boot device */
	if (MB_CHECK_FLAG(mbi->flags, 2)) {
		char str[3];
		uint_t boot_device = (mbi->boot_device >> 24) & 0xff;
		if (boot_device == MB_NETWORK_DRIVE)
			netboot++;
		(void) snprintf(str, 3, "%x", boot_device);
		(void) bsetprop(NULL, "bios-boot-device", str, 3);
	} else {	/* assume netboot? */
		netboot++;
	}

	/*
	 * In the netboot case, drives_info is overloaded with
	 * the dhcp ack. This is not multiboot compliant and
	 * requires special pxegrub!
	 */
	if (netboot) {
		if (verbosemode)
			printf("booting from network\n");

		if (mbi->drives_length == 0) {
			if (verbosemode) {
				printf("no network info, "
				    "need a GRUB with Solaris enhancements\n");
			}
		} else {
			struct sol_netinfo *sip =
				(struct sol_netinfo *)mbi->drives_addr;
			switch (sip->sn_infotype) {
			case SN_TYPE_BOOTP:
				(void) bsetprop(NULL, BP_BOOTP_RESPONSE,
				    (void *)mbi->drives_addr,
				    mbi->drives_length);
				break;
			case SN_TYPE_RARP:
				setup_rarp_props(sip);
				break;
			default:
				printf("invalid network info: type %d\n",
				    sip->sn_infotype);
				break;
			};
		}
	}

	/* dummy properties needed by Install miniroot */
	(void) bsetprop(NULL,
		"stdout", &stdout_val, sizeof (stdout_val));
}

#define	BUFLEN	64

static void
setup_rarp_props(struct sol_netinfo *sip)
{
	char *buf = bkmem_alloc(BUFLEN);	/* to hold ip/mac addrs */
	uint8_t *val;

	val = (uint8_t *)&sip->sn_ciaddr;
	(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
	    val[0], val[1], val[2], val[3]);
	(void) bsetprop(NULL, BP_HOST_IP, buf, strlen(buf) + 1);

	val = (uint8_t *)&sip->sn_siaddr;
	(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
	    val[0], val[1], val[2], val[3]);
	(void) bsetprop(NULL, BP_SERVER_IP, buf, strlen(buf) + 1);

	if (sip->sn_giaddr != 0) {
		val = (uint8_t *)&sip->sn_giaddr;
		(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
		    val[0], val[1], val[2], val[3]);
		(void) bsetprop(NULL, BP_ROUTER_IP, buf, strlen(buf) + 1);
	}

	if (sip->sn_netmask != 0) {
		val = (uint8_t *)&sip->sn_netmask;
		(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
		    val[0], val[1], val[2], val[3]);
		(void) bsetprop(NULL, BP_SUBNET_MASK, buf, strlen(buf) + 1);
	}

	if (sip->sn_mactype != 4 || sip->sn_maclen != 6) {
		printf("unsupported mac type %d, mac len %d\n",
		    sip->sn_mactype, sip->sn_maclen);
		return;
	}

	val = sip->sn_macaddr;
	(void) snprintf(buf, BUFLEN, "%x:%x:%x:%x:%x:%x",
	    val[0], val[1], val[2], val[3], val[4], val[5]);
	(void) bsetprop(NULL, BP_BOOT_MAC, buf, strlen(buf) + 1);
}
