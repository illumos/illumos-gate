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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>

static char *pcitool_usage_text[] = {
"Usage:",
"Probe mode:",
" %s [ <PCI nexus node> ] [ -a ] [ -p ] [ -v ] [ -q ]",
"",
" %s <PCI nexus node> [ -p [ bus=<bus>,dev=<dev>,func=<func> ] [ -v ] [ -q ]",
" %s <PCI nexus node> [ -p [ bdf=<bus>.<dev>.<func> ] [ -v ] [-q ]",
"",
"Register peek/poke mode:",
" %s <PCI nexus node>",
"  [   -n bank=<register bank>",
"         where register bank is 0 for mapped jbus space and 1 for pcie space",
"         (only on applicable platforms)",
"",
"      -n base=<base address>",
"         where base address is a physical base address of a register bank",
"         (only on applicable platforms (e.g. sun4v) where bank info is "
	"unavailable)",
"",
"      -d bus=<bus>,dev=<dev>,func=<func>,bank=<register bank>",
"      -d bdf=<bus>.<dev>.<func>,bank=<register bank>",
"",
"      -d bus=<bus>,dev=<dev>,func=<func> | bdf=<bus>.<dev>.<func> ,",
"	  [ config | bar0 | bar1 | bar2 | bar3 | bar4 | bar5 | rom ]",
"	  (spaces added for clarity but are not allowed in the command)",
"",
"  -n and -d options may also include:",
"",
"  [ -w <value to write> ] [ -r ]",
"  [ -o <offset> ]",
"  [ -s 1 | 2 | 4 | 8 ]",
"  [ -e b | l ]",
"  [ -l ]",
"  [ -b <number bytes to dump> [ -c ] [ -x ] ]",
"  [ -v ]",
"  [ -q ]",
"",
"  -n may also include:",
"",
"  [ -y ]",
"",
"Interrupt mode:",
" X86:",
" %s pci@<unit-address> -i <cpu#,ino#> | all",
"       [ -r [ -c ] |  -w <cpu#> [ -g ] ] [ -v ] [ -q ]",
" SPARC:",
" %s pci@<unit-address> -i <ino#> | all",
"       [ -r [ -c ] |  -w <cpu#> [ -g ] ] [ -v ] [ -q ]",
" %s pci@<unit-address> -m <msi#> | all",
"       [ -r [ -c ] |  -w <cpu#> [ -g ] ] [ -v ] [ -q ]",
"",
"where",
"",
"pci@<unit-address> is a node from /devices, with \"/devices\" stripped off.",
"For example: /pci@0,0",
"",
"-v gives verbose output for all modes.",
"",
"-q suppresses error output (except for commandline parsing errors) for all "
	"modes",
"   (Note that errno status is returned to the shell upon termination.)",
"",
"Online help mode:",
" %s -h",
"   Prints this message.",
"",
"Probe mode",
"----------",
"",
"-p [ bus=<bus>,dev=<dev>,func=<func> | bdf=<bus>.<dev>.<func> ]",
"     Specify bus, device and/or function of devices to search for and dump.",
"",
"-a Probe all buses.  By default, pcitool checks the PCI nexus node's",
"bus-range property to restrict which buses are probed.  This option",
"cannot be combined with an explicit bus specification.",
"",
"If a PCI nexus node is specified, pcitool looks only for devices",
"under that node.  If no PCI nexus node is specified, pcitool looks",
"for devices under all PCI nexus nodes.  PCI nexus nodes, which can",
"be used for other pcitool commands, are printed at the top of each tree.",
"",
"Non-verbose probe mode prints config register data as follows:",
"  aa bb c dddd eeee ffff gggg hh iiiiii jj kk ll mm",
"  where...",
"    a = pci bus number",
"    b = pci device number",
"    c = pci function number",
"    d = vendor ID",
"    e = device ID",
"    f = command register",
"    g = status register",
"    h = revision ID",
"    i = class code",
"    j = cache line size",
"    k = latency timer",
"    l = header type",
"    m = built in self test register (bist)",
"",
"Register peek/poke mode",
"-----------------------",
"",
"-n requests nexus node info.",
"   Specify desired nexus register using -o <register offset>",
"",
"-d requests device (leaf) node info.",
"   Specify bus, dev, function bits (from probe mode) as hex numbers.",
"   Bank is specified in one of the following ways:",
"     By value: 0 == config space, 1 == BAR0, 2 == BAR1, ..., 6 == BAR5, "
	"7 == ROM",
"     By BAR (bus addr reg): config, bar0, bar1, bar2, bar3, bar4, bar5, rom",
"",
"Above peek/poke mode selections take the following options:",
"",
"-r for reading (default)",
"-w <value> for writing",
"-w <value> -r for writing a value followed by a readback",
"",
"-o <offset> to specify an offset within the requested address space",
"",
"-s <size specifier>: 1, 2, 4 or 8 bytes, default 4",
"   (8-byte transfers on supported platforms only)",
"",
"-e <endian specifier>: b or l (ell), default is l for little endian>",
"",
"-l to do repetitious accesses to/from the same location(s)",
"",
"-b <number of bytes to dump> [ -c ] to get a formatted multiple register dump",
"   starting at the offset given.  Hex bytes are always dumped.",
"   -c dumps characters as well.  "
	"Non-printable characters are dumped as \"@\".",
"   -x keeps going on errors, and prints err characters as X",
"",
"Above nexus peek/poke mode selections take the following additional option:",
"",
"-y to confirm a base_addr without being prompted interactively",
"",
"NOTE: Some platforms (i.e. SPARC) return peek/poke errors as failed ioctls;",
"    Other platforms (i.e. X86) return peek/poke errors as FF values.",
"",
"All numeric values are in HEX",
"",
"Interrupt mode",
"--------------",
"",
"-i <[cpu#],ino#> changes or retrieves current interrupts information of given",
"   nexus and given INO. The special value of 'all' can be used to select all",
"   INOs.",
"",
"-m <[cpu#],msi#> changes or retrieves current interrupts information of given",
"   nexus and given MSI/X. The special value of 'all' can be used to select",
"   all MSI/Xs.",
"",
"   Note: [cpu#] is available on x86 platform, is to identify exclusive vector",
"   with ino# at the same time. [cpu#] is not supported on SPARC platform.",
"",
"   Note: On x86 platforms, both INOs and MSI/Xs are mapped to the same",
"   interrupt vectors. Use -i option to retrieve and reroute any interrupt",
"   vectors (both INO and MSI/Xs).  So, -m option is not required on x86",
"   platforms. Hence it is not supported.",
"",
"   A specific INO or MSI/X must be selected if -w specified.",
"",
"-w <cpu#> [ -g ] to change an INO or MSI/X <->CPU binding.",
"",
"   Note: On certain platforms (e.g. X86), multiple MSI interrupts of a single",
"   function need to be moved together.  Use -g to do this.  -g works only on",
"   supported platforms and only for groups of MSI interrupts.  When -g is",
"   used, INO must be the lowest-numbered vector of the group.  (Use the mdb",
"   ::interrupts dcmd to discover groups of MSI vectors.)  The size of the",
"   group is determined internally.  (\"Groups\" of size 1 are accepted.)",
"",
"-r [ -c ] for displaying ino or msi <->CPU bindings of all selected INO/MSIs",
"   on a given nexus.  -c optionally dumps controller information.",
"",
"   All relevant enabled INO/MSI/Xs supporting non-nexus device interrupts",
"   will be printed.  For each printed INO/MSI/X, all supported devices and",
"   their CPU binding will be displayed.  On some platforms, INOs dedicated",
"   to the root nexus will be shown and marked with \"(Internal)\".",
"",
"When neither -r nor -w are specified, -r is the default.",
NULL
};


/*
 * Print usage statement.
 *
 * Text is too large for many print statements.
 *
 * Instead, loop through the array of strings in pcitool_usage_text.
 * Print program name when %s is in the text.
 */
void
usage(char *name)
{
	int i;

	for (i = 0; pcitool_usage_text[i] != NULL; i++) {
		(void) printf(pcitool_usage_text[i], name);
		(void) printf("\n");
	}
}
