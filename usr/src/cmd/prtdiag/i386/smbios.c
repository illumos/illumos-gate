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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2015 Joyent, Inc.
 */

/*
 * x86 System Management BIOS prtdiag
 *
 * Most modern x86 systems support a System Management BIOS, which is a memory
 * buffer filled in by the BIOS at boot time that describes the hardware.  This
 * data format is described by DMTF specification DSP0134 (see http://dmtf.org)
 * This file implements a rudimentary prtdiag(8) display using the SMBIOS.
 * Access to the data is provided by libsmbios: see <sys/smbios.h> for info.
 *
 * NOTE: It is important to understand that x86 hardware varies extremely
 * widely and that the DMTF SMBIOS specification leaves way too much latitude
 * for implementors, and provides no standardized validation mechanism.  As
 * such, it is not uncommon to find out-of-spec SMBIOSes or fields that
 * contain strange and possibly even incorrect information.  As such, this
 * file should not be extended to report every SMBIOS tidbit or structure in
 * the spec unless we have good reason to believe it tends to be reliable.
 *
 * Similarly, the prtdiag(8) utility itself should not be used to spit out
 * every possible bit of x86 configuration data from every possible source;
 * otherwise this code will become an unmaintainable and untestable disaster.
 * Extensions to prtdiag should prefer to use more stable kernel mechanisms
 * that actually discover the true hardware when such subsystems are available,
 * and should generally limit themselves to commonly needed h/w data.  As such,
 * extensions to x86 prtdiag should focus on integration with the device tree.
 *
 * The prtdiag(8) utility is for service personnel and system administrators:
 * it is not your personal ACPI disassembler or CPUID decoder ring.  The
 * complete SMBIOS data is available from smbdump(1), and other specialized
 * tools can be created to display the state of other x86 features, especially
 * when that information is more for kernel developers than box administrators.
 */

#include <smbios.h>
#include <alloca.h>
#include <locale.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <pcidb.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <sys/fm/protocol.h>

static pcidb_hdl_t *prt_php;

/*ARGSUSED*/
static int
do_procs(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	smbios_processor_t p;
	smbios_info_t info;
	const char *v;
	char *s;
	size_t n;

	if (sp->smbstr_type == SMB_TYPE_PROCESSOR &&
	    smbios_info_processor(shp, sp->smbstr_id, &p) != SMB_ERR &&
	    smbios_info_common(shp, sp->smbstr_id, &info) != SMB_ERR &&
	    SMB_PRSTATUS_PRESENT(p.smbp_status)) {

		/*
		 * Obtaining a decent string for the type of processor is
		 * messy: the BIOS has hopefully filled in the SMBIOS record.
		 * If so, strip trailing spaces and \r (seen in some BIOSes).
		 * If not, fall back to the family name for p.smbp_family.
		 */
		if (info.smbi_version != NULL && *info.smbi_version != '\0') {
			n = strlen(info.smbi_version);
			v = s = alloca(n + 1);
			(void) strcpy(s, info.smbi_version);

			if (s[n - 1] == '\r')
				s[--n] = '\0';

			while (n != 0 && isspace(s[n - 1]))
				s[--n] = '\0';

		} else if ((v = smbios_processor_family_desc(
		    p.smbp_family)) == NULL) {
			v = gettext("Unknown");
		}

		(void) printf(gettext("%-32s %s\n"), v, info.smbi_location);
	}

	return (0);
}

/*
 * NOTE: It would be very convenient to print the DIMM size in do_memdevs.
 * Unfortunately, SMBIOS can only be relied upon to tell us whether a DIMM is
 * present or not (smbmd_size == 0).  Some BIOSes do fill in an accurate size
 * for DIMMs, whereas others fill in the maximum size, and still others insert
 * a wrong value.  Sizes will need to wait for x86 memory controller interfaces
 * or integration with IPMI, which can actually read the true DIMM SPD data.
 */
/*ARGSUSED*/
static int
do_memdevs(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	smbios_memdevice_t md;

	if (sp->smbstr_type == SMB_TYPE_MEMDEVICE &&
	    smbios_info_memdevice(shp, sp->smbstr_id, &md) != SMB_ERR) {

		const char *t = smbios_memdevice_type_desc(md.smbmd_type);
		char buf[8];

		if (md.smbmd_set != (uint8_t)-1)
			(void) snprintf(buf, sizeof (buf), "%u", md.smbmd_set);
		else
			(void) strcpy(buf, "-");

		(void) printf(gettext("%-11s %-6s %-3s %-19s %s\n"),
		    t ? t : gettext("Unknown"),
		    md.smbmd_size ? gettext("in use") : gettext("empty"),
		    buf, md.smbmd_dloc, md.smbmd_bloc);
	}

	return (0);
}

/*ARGSUSED*/
static int
do_obdevs(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	smbios_obdev_t *argv;
	int i, argc;

	if (sp->smbstr_type == SMB_TYPE_OBDEVS &&
	    (argc = smbios_info_obdevs(shp, sp->smbstr_id, 0, NULL)) > 0) {
		argv = alloca(sizeof (smbios_obdev_t) * argc);
		(void) smbios_info_obdevs(shp, sp->smbstr_id, argc, argv);
		for (i = 0; i < argc; i++)
			(void) printf(gettext("%s\n"), argv[i].smbd_name);
	}

	return (0);
}

/*ARGSUSED*/
static int
do_slot_mapping_cb(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err, ret;
	nvlist_t *rsrc = NULL;
	const char *match = arg;
	char *s, *fmri = NULL;
	char *didstr = NULL, *driver = NULL, *vidstr = NULL;
	boolean_t printed = B_FALSE;

	ret = TOPO_WALK_NEXT;
	if (topo_node_resource(node, &rsrc, &err) < 0)
		goto next;
	if (topo_fmri_nvl2str(thp, rsrc, &fmri, &err) < 0)
		goto next;

	if ((s = strstr(fmri, match)) == NULL)
		goto next;
	if (s[strlen(match)] != '\0')
		goto next;

	/* At this point we think we've found a match */
	ret = TOPO_WALK_TERMINATE;
	if (topo_prop_get_string(node, TOPO_PGROUP_IO, TOPO_IO_DRIVER, &driver,
	    &err) != 0)
		driver = NULL;

	if (topo_prop_get_string(node, TOPO_PGROUP_PCI, TOPO_PCI_VENDID,
	    &vidstr, &err) != 0)
		goto next;

	if (topo_prop_get_string(node, TOPO_PGROUP_PCI, TOPO_PCI_DEVID,
	    &didstr, &err) != 0)
		goto next;

	if (prt_php != NULL) {
		long vid, did;

		vid = strtol(vidstr, NULL, 16);
		did = strtol(didstr, NULL, 16);
		if (vid >= 0 && vid <= UINT16_MAX &&
		    did >= 0 && did <= UINT16_MAX) {
			pcidb_device_t *pdev;

			pdev = pcidb_lookup_device(prt_php, vid, did);
			if (pdev != NULL) {
				pcidb_vendor_t *pvend;
				pvend = pcidb_device_vendor(pdev);
				(void) printf(gettext(", %s %s (%s)"),
				    pcidb_vendor_name(pvend),
				    pcidb_device_name(pdev),
				    driver != NULL ? driver : "<unknown>");
				printed = B_TRUE;
			}
		}
	}

	if (printed == B_FALSE) {
		(void) printf(gettext(", pci%s,%s (%s)"), vidstr, didstr,
		    driver != NULL ? driver : "<unknown>");
	}
next:
	topo_hdl_strfree(thp, didstr);
	topo_hdl_strfree(thp, driver);
	topo_hdl_strfree(thp, vidstr);
	topo_hdl_strfree(thp, fmri);
	nvlist_free(rsrc);
	return (ret);
}

static void
do_slot_mapping(smbios_slot_t *s, topo_hdl_t *thp)
{
	int err;
	uint_t dev, func;
	topo_walk_t *twp;
	char pciex[256];

	/*
	 * Bits 7:3 are the device number and bits 2:0 are the function.
	 */
	dev = s->smbl_df >> 3;
	func = s->smbl_df & 0x7;

	(void) snprintf(pciex, sizeof (pciex), "%s=%u/%s=%u/%s=%d",
	    PCIEX_BUS, s->smbl_bus, PCIEX_DEVICE, dev, PCIEX_FUNCTION, func);

	twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, do_slot_mapping_cb, pciex,
	    &err);
	if (twp == NULL)
		return;

	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
}

/*ARGSUSED*/
static int
do_slots(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	smbios_slot_t s;

	if (sp->smbstr_type == SMB_TYPE_SLOT &&
	    smbios_info_slot(shp, sp->smbstr_id, &s) != SMB_ERR) {

		const char *t = smbios_slot_type_desc(s.smbl_type);
		const char *u = smbios_slot_usage_desc(s.smbl_usage);

		(void) printf(gettext("%-3u %-9s %-16s %s"),
		    s.smbl_id, u ? u : gettext("Unknown"),
		    t ? t : gettext("Unknown"), s.smbl_name);

		/*
		 * If the slot isn't of a type where this makes sense, then
		 * SMBIOS will populate any of these members with the value
		 * 0xff. Therefore if we find any of them set there, we just
		 * ignore it for now.
		 */
		if (s.smbl_sg != 0xff && s.smbl_bus != 0xff &&
		    s.smbl_df != 0xff && arg != NULL)
			do_slot_mapping(&s, arg);

		(void) printf(gettext("\n"));
	}

	return (0);
}

/*ARGSUSED*/
int
do_prominfo(int opt_v, char *progname, int opt_l, int opt_p)
{
	smbios_hdl_t *shp;
	smbios_system_t sys;
	smbios_bios_t bios;
	smbios_ipmi_t ipmi;
	smbios_info_t info;
	topo_hdl_t *thp;
	char *uuid;

	const char *s;
	id_t id;
	int err;

	if ((shp = smbios_open(NULL, SMB_VERSION, 0, &err)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: failed to open SMBIOS: %s\n"),
		    progname, smbios_errmsg(err));
		return (1);
	}

	if ((id = smbios_info_system(shp, &sys)) != SMB_ERR &&
	    smbios_info_common(shp, id, &info) != SMB_ERR) {
		(void) printf(gettext("System Configuration: %s %s\n"),
		    info.smbi_manufacturer, info.smbi_product);
	} else {
		(void) fprintf(stderr,
		    gettext("%s: failed to get system info: %s\n"),
		    progname, smbios_errmsg(smbios_errno(shp)));
	}

	if (smbios_info_bios(shp, &bios) != SMB_ERR) {
		(void) printf(gettext("BIOS Configuration: %s %s %s\n"),
		    bios.smbb_vendor, bios.smbb_version, bios.smbb_reldate);
	} else {
		(void) fprintf(stderr,
		    gettext("%s: failed to get bios info: %s\n"),
		    progname, smbios_errmsg(smbios_errno(shp)));
	}

	if (smbios_info_ipmi(shp, &ipmi) != SMB_ERR) {
		if ((s = smbios_ipmi_type_desc(ipmi.smbip_type)) == NULL)
			s = gettext("Unknown");

		(void) printf(gettext("BMC Configuration: IPMI %u.%u (%s)\n"),
		    ipmi.smbip_vers.smbv_major, ipmi.smbip_vers.smbv_minor, s);
	}

	/*
	 * Silently swallow all libtopo and libpcidb related errors.
	 */
	uuid = NULL;
	if ((thp = topo_open(TOPO_VERSION, NULL, &err)) != NULL) {
		if ((uuid = topo_snap_hold(thp, NULL, &err)) == NULL) {
			topo_close(thp);
			thp = NULL;
		}
	}

	prt_php = pcidb_open(PCIDB_VERSION);

	(void) printf(gettext(
	    "\n==== Processor Sockets ====================================\n"));

	(void) printf(gettext("\n%-32s %s"), "Version", "Location Tag");

	(void) printf(gettext(
	    "\n-------------------------------- --------------------------\n"));
	(void) smbios_iter(shp, do_procs, NULL);

	(void) printf(gettext(
	    "\n==== Memory Device Sockets ================================\n"));

	(void) printf(gettext("\n%-11s %-6s %-3s %-19s %s"),
	    "Type", "Status", "Set", "Device Locator", "Bank Locator");

	(void) printf(gettext(
	    "\n----------- ------ --- ------------------- ----------------\n"));
	(void) smbios_iter(shp, do_memdevs, NULL);

	(void) printf(gettext(
	    "\n==== On-Board Devices =====================================\n"));
	(void) smbios_iter(shp, do_obdevs, NULL);

	(void) printf(gettext(
	    "\n==== Upgradeable Slots ====================================\n"));

	(void) printf(gettext("\n%-3s %-9s %-16s %s"),
	    "ID", "Status", "Type", "Description");

	(void) printf(gettext(
	    "\n--- --------- ---------------- ----------------------------\n"));
	(void) smbios_iter(shp, do_slots, thp);

	smbios_close(shp);

	topo_hdl_strfree(thp, uuid);
	if (thp != NULL) {
		topo_snap_release(thp);
		topo_close(thp);
	}
	pcidb_close(prt_php);

	return (0);
}
