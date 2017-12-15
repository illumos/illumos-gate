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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * This is the user interface module for the pcitool.  It checks commandline
 * arguments and options and stores them in a pcitool_uiargs_t structure passed
 * back to the rest of the program for processing.
 *
 * Please see pcitool_usage.c for a complete commandline description.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inttypes.h>
#include <sys/types.h>
#include <sys/param.h>
#include <strings.h>
#include <errno.h>
#include <sys/pci.h>

#include <sys/pci_tools.h>

#include "pcitool_ui.h"

/*
 * Uncomment the following for useful debugging / development options for this
 * module only.
 */

/* #define	DEBUG	1		*/
/* #define	STANDALONE	1	*/

#define		DEVNAME_START_PCI	"/pci"
#define		DEVNAME_START_NIU	"/niu"

/* Default read/write size when -s not specified. */
#define	DEFAULT_SIZE	4

/* For get_value64 */
#define	HEX_ONLY	B_TRUE
#define	BASE_BY_PREFIX	B_FALSE

#define	BITS_PER_BYTE	8

/*
 * This defines which main options can be specified by the user.
 * Options with colons after them require arguments.
 */
static char *opt_string = ":n:d:i:m:p:rw:o:s:e:b:vaqlcxgy";

/* This defines options used singly and only by themselves (no nexus). */
static char *no_dev_opt_string = "ahpqv";

static void print_bad_option(char *argv[], int optopt, char *optarg);
static boolean_t get_confirmation(void);
static int get_value64(char *value_str, uint64_t *value, boolean_t hex_only);
static int parse_nexus_opts(char *input, uint64_t *flags_arg, uint8_t *bank_arg,
    uint64_t *base_addr_arg);
static int extract_bdf_arg(char *cvalue, char *fld, uint64_t fld_flag,
    uint64_t *all_flags, uint8_t *ivalue);
static int extract_bdf(char *value, char **bvalue_p, char **dvalue_p,
    char **fvalue_p);
static int parse_device_opts(char *input, uint64_t *flags_arg,
    uint8_t *bus_arg, uint8_t *device_arg, uint8_t *func_arg,
    uint8_t *bank_arg);
static int parse_ino_opts(char *input, uint64_t *flags_arg,
    uint32_t *cpu_arg, uint8_t *ino_arg);
static int parse_msi_opts(char *input, uint64_t *flags_arg, uint16_t *msi_arg);
static int parse_intr_set_opts(char *input, uint64_t *flags_arg,
    uint32_t *cpu_arg);
static int parse_probeone_opts(char *input, uint64_t *flags_arg,
    uint8_t *bus_arg, uint8_t *device_arg, uint8_t *func_arg);

#ifdef DEBUG
void dump_struct(pcitool_uiargs_t *dump_this);
#endif

/* Exported functions. */

/*
 * Main commandline argument parsing routine.
 *
 * Takes argc and argv straight from the commandline.
 * Returns a pcitool_uiargs_t with flags of options specified, and values
 * associated with them.
 */
int
get_commandline_args(int argc, char *argv[], pcitool_uiargs_t *parsed_args)
{
	int c;				/* Current option being processed. */
	boolean_t error = B_FALSE;
	boolean_t confirm = B_FALSE;
	uint64_t recv64;

	/* Needed for getopt(3C) */
	extern char *optarg;	/* Current commandline string. */
	extern int optind;	/* Index of current commandline string. */
	extern int optopt;	/* Option (char) which is missing an operand. */
	extern int opterr;	/* Set to 0 to disable getopt err reporting. */

	opterr = 0;

	bzero(parsed_args, sizeof (pcitool_uiargs_t));

	/* No args.  probe mode accounting for bus ranges, nonverbose. */
	if (argc == 1) {
		usage(argv[0]);
		parsed_args->flags = 0;
		return (SUCCESS);
	}

	/* 1st arg is not a device name. */
	if ((strstr(argv[1], DEVNAME_START_PCI) != argv[1]) &&
	    (strstr(argv[1], DEVNAME_START_NIU) != argv[1])) {

		/* Default is to probe all trees accounting for bus ranges. */
		parsed_args->flags = PROBEALL_FLAG | PROBERNG_FLAG;

		/* Loop thru the options until complete or an error is found. */
		while (((c = getopt(argc, argv, no_dev_opt_string)) != -1) &&
		    (error == B_FALSE)) {

			switch (c) {

			/* Help requested. */
			case 'h':
				usage(argv[0]);
				parsed_args->flags = 0;
				return (SUCCESS);

			case 'p':
				/* Take default probe mode */
				break;

			case 'a':
				/*
				 * Enable display of ALL bus numbers.
				 *
				 * This takes precidence over PROBERNG as -a
				 * is explicitly specified.
				 */
				parsed_args->flags &= ~PROBERNG_FLAG;
				break;

			case 'q':
				parsed_args->flags |= QUIET_FLAG;
				break;

			/* Verbose mode for full probe. */
			case 'v':
				parsed_args->flags |= VERBOSE_FLAG;
				break;

			default:
				error = B_TRUE;
				break;
			}
		}

		/* Check for values straggling at the end of the command. */
		if (optind != argc) {
			(void) fprintf(stderr, "%s: Unrecognized parameter "
			    "at the end of the command.\n", argv[0]);
			error = B_TRUE;
		}

		if (error) {
			print_bad_option(argv, optopt, optarg);
			return (FAILURE);
		}

		return (SUCCESS);
	}

	/* Device node specified on commandline. */

	/* Skip argv[1] before continuing below. */
	optind++;

	/* Loop through the options until complete or an error is found. */
	while (((c = getopt(argc, argv, opt_string)) != -1) &&
	    (error == B_FALSE)) {

		switch (c) {

		/* Nexus */
		case 'n':
			if (parsed_args->flags & (LEAF_FLAG |
			    NEXUS_FLAG | INTR_FLAG | PROBE_FLAGS)) {
				(void) fprintf(stderr, "%s: -n set with "
				    "-d, -p or -i or is set twice\n", argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= NEXUS_FLAG;
			if (parse_nexus_opts(optarg, &parsed_args->flags,
			    &parsed_args->bank, &parsed_args->base_address) !=
			    SUCCESS) {
				(void) fprintf(stderr,
				    "%s: Error parsing -n options\n", argv[0]);
				error = B_TRUE;
				break;
			}
			break;

		/* Device (leaf node) */
		case 'd':
			if (parsed_args->flags & (LEAF_FLAG |
			    NEXUS_FLAG | INTR_FLAG | PROBE_FLAGS)) {
				(void) fprintf(stderr, "%s: -d set with "
				    "-n, -p or -i or is set twice\n", argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= LEAF_FLAG;
			if (parse_device_opts(optarg, &parsed_args->flags,
			    &parsed_args->bus, &parsed_args->device,
			    &parsed_args->function,
			    &parsed_args->bank) != SUCCESS) {
				(void) fprintf(stderr,
				    "%s: Error parsing -d options\n", argv[0]);
				error = B_TRUE;
				break;
			}
			break;

		/* Interrupt */
		case 'i':
			if (parsed_args->flags & (LEAF_FLAG |
			    NEXUS_FLAG | INTR_FLAG | PROBE_FLAGS)) {
				(void) fprintf(stderr, "%s: -i set with -m, "
				    "-n, -d or -p or is set twice\n", argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= INTR_FLAG;

			/* parse input to get ino value. */
			if (parse_ino_opts(optarg, &parsed_args->flags,
			    &parsed_args->old_cpu,
			    &parsed_args->intr_ino) != SUCCESS) {
				(void) fprintf(stderr,
				    "%s: Error parsing interrupt options\n",
				    argv[0]);
				error = B_TRUE;
			}
			break;
		/* Interrupt */
		case 'm':
			if (parsed_args->flags & (LEAF_FLAG |
			    NEXUS_FLAG | INTR_FLAG | PROBE_FLAGS)) {
				(void) fprintf(stderr, "%s: -m set with -i, "
				    "-n, -d or -p or is set twice\n", argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= INTR_FLAG;

			/* parse input to get msi value. */
			if (parse_msi_opts(optarg, &parsed_args->flags,
			    &parsed_args->intr_msi) != SUCCESS) {
				(void) fprintf(stderr,
				    "%s: Error parsing interrupt options\n",
				    argv[0]);
				error = B_TRUE;
			}
			break;
		/* Probe */
		case 'p':
			if (parsed_args->flags & (LEAF_FLAG |
			    NEXUS_FLAG | INTR_FLAG | PROBE_FLAGS)) {
				(void) fprintf(stderr, "%s: -p set with "
				    "-n, -d or -i or is set twice\n", argv[0]);
				error = B_TRUE;
				break;
			}

			/* Process -p with no dedicated options to it. */
			if (optarg[0] == '-') {
				optind--;

				/* Probe given tree observing ranges */
				parsed_args->flags |=
				    (PROBETREE_FLAG | PROBERNG_FLAG);
				continue;
			}

			/* parse input to get ino value. */
			if (parse_probeone_opts(optarg, &parsed_args->flags,
			    &parsed_args->bus, &parsed_args->device,
			    &parsed_args->function) != SUCCESS) {
				(void) fprintf(stderr,
				    "%s: Error parsing probe options\n",
				    argv[0]);
				error = B_TRUE;
			} else {
				/*
				 * parse_probeone_opts found options to
				 * set up bdf.
				 */
				parsed_args->flags |= PROBEDEV_FLAG;
			}
			break;

		/* Probe all busses */
		case 'a':
			/* Must follow -p, and -p must have no bdf. */
			if (!(parsed_args->flags & PROBETREE_FLAG)) {
				error = B_TRUE;
				break;
			}

			parsed_args->flags &= ~PROBERNG_FLAG;
			break;

		/* Read */
		case 'r':
			if (!(parsed_args->flags &
			    (LEAF_FLAG | NEXUS_FLAG | INTR_FLAG))) {
				error = B_TRUE;
				break;
			}

			/*
			 * Allow read and write to be set together for now,
			 * since this means write then read back for device and
			 * nexus accesses.  Check for this and disallow with
			 * interrupt command later.
			 */
			parsed_args->flags |= READ_FLAG;
			break;

		/* Write */
		case 'w':
			if (!(parsed_args->flags &
			    (LEAF_FLAG | NEXUS_FLAG | INTR_FLAG))) {
				error = B_TRUE;
				break;
			}
			if (parsed_args->flags & WRITE_FLAG) {
				(void) fprintf(stderr, "%s: -w set twice\n",
				    argv[0]);
				error = B_TRUE;
				break;
			}

			/*
			 * For device and nexus, get a single register value
			 * to write.
			 */
			if (parsed_args->flags & (NEXUS_FLAG | LEAF_FLAG)) {
				parsed_args->flags |= WRITE_FLAG;
				if (get_value64(optarg,
				    &parsed_args->write_value, HEX_ONLY) !=
				    SUCCESS) {
					(void) fprintf(stderr,
					    "%s: Error reading value to "
					    "write.\n", argv[0]);
					error = B_TRUE;
					break;
				}

			/* For interrupt,  parse input to get cpu value. */
			} else if (parsed_args->flags & INTR_FLAG) {
				parsed_args->flags |= WRITE_FLAG;
				if (parse_intr_set_opts(optarg,
				    &parsed_args->flags,
				    &parsed_args->intr_cpu) != SUCCESS) {
					(void) fprintf(stderr, "%s: Error "
					    "parsing interrupt options.\n",
					    argv[0]);
					error = B_TRUE;
					break;
				}

			} else {
				error = B_TRUE;
				break;
			}
			break;

		/* Offset */
		case 'o':
			if (!(parsed_args->flags & (LEAF_FLAG | NEXUS_FLAG))) {
				error = B_TRUE;
				break;
			}
			if (parsed_args->flags & OFFSET_FLAG) {
				(void) fprintf(stderr, "%s: -o set twice\n",
				    argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= OFFSET_FLAG;
			if (get_value64(optarg, &recv64, HEX_ONLY) != SUCCESS) {
				(void) fprintf(stderr,
				    "%s: Error in offset argument\n", argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->offset = (uint32_t)recv64;
			if (parsed_args->offset != recv64) {
				(void) fprintf(stderr, "%s: Offset argument "
				    "too large for 32 bits\n", argv[0]);
				error = B_TRUE;
				break;
			}
			break;

		/* Size */
		case 's':
			if (!(parsed_args->flags & (LEAF_FLAG | NEXUS_FLAG))) {
				error = B_TRUE;
				break;
			}
			if (parsed_args->flags & SIZE_FLAG) {
				(void) fprintf(stderr, "%s: -s set twice\n",
				    argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= SIZE_FLAG;
			if (get_value64(optarg, &recv64, HEX_ONLY) != SUCCESS) {
				(void) fprintf(stderr,
				    "%s: Error in size argument\n", argv[0]);
				error = B_TRUE;
				break;
			}
			switch (recv64) {
			case 1:
			case 2:
			case 4:
			case 8:
				break;
			default:
				error = B_TRUE;
				(void) fprintf(stderr,
				    "%s: Error in size argument\n", argv[0]);
				break;
			}
			parsed_args->size |= (uint8_t)recv64;
			break;

		/* Endian. */
		case 'e':
			if (!(parsed_args->flags & (LEAF_FLAG | NEXUS_FLAG))) {
				error = B_TRUE;
				break;
			}
			if (parsed_args->flags & ENDIAN_FLAG) {
				(void) fprintf(stderr, "%s: -e set twice\n",
				    argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= ENDIAN_FLAG;

			/* Only a single character allowed. */
			if (optarg[1] != '\0') {
				(void) fprintf(stderr,
				    "%s: Error in endian argument\n", argv[0]);
				error = B_TRUE;
				break;
			}

			switch (optarg[0]) {
			case 'b':
				parsed_args->big_endian = B_TRUE;
				break;
			case 'l':
				break;
			default:
				(void) fprintf(stderr,
				    "%s: Error in endian argument\n", argv[0]);
				error = B_TRUE;
				break;
			}
			break;

		/* (Byte)dump */
		case 'b':
			if (!(parsed_args->flags & (LEAF_FLAG | NEXUS_FLAG))) {
				error = B_TRUE;
				break;
			}
			if (parsed_args->flags & BYTEDUMP_FLAG) {
				(void) fprintf(stderr, "%s: -b set twice\n",
				    argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= BYTEDUMP_FLAG;
			if (get_value64(optarg, &recv64, HEX_ONLY) != SUCCESS) {
				(void) fprintf(stderr, "%s: Error in "
				    "bytedump argument\n", argv[0]);
				error = B_TRUE;
				break;
			}
			parsed_args->bytedump_amt = (uint32_t)recv64;
			if (parsed_args->bytedump_amt != recv64) {
				(void) fprintf(stderr, "%s: Bytedump amount "
				    "too large for 32 bits\n", argv[0]);
				error = B_TRUE;
				break;
			}
			break;

		/* Verbose. */
		case 'v':
			parsed_args->flags |= VERBOSE_FLAG;
			break;

		/*
		 * Quiet - no errors reported as messages.
		 * (Status still returned by program, however.)
		 */
		case 'q':
			parsed_args->flags |= QUIET_FLAG;
			break;

		/* Loop. */
		case 'l':
			parsed_args->flags |= LOOP_FLAG;
			break;

		/*
		 * Dump characters with bytedump (-b).
		 * Show controller info with -i.
		 */
		case 'c':
			if (parsed_args->flags & BYTEDUMP_FLAG) {
				parsed_args->flags |= CHARDUMP_FLAG;

			} else if (parsed_args->flags & INTR_FLAG) {
				parsed_args->flags |= SHOWCTLR_FLAG;

			} else {
				error = B_TRUE;
			}
			break;

		/* Continue on errors with bytedump (-b). */
		case 'x':
			if (!(parsed_args->flags & BYTEDUMP_FLAG)) {
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= ERRCONT_FLAG;
			break;

		case 'g':
			if (!(parsed_args->flags & INTR_FLAG)) {
				error = B_TRUE;
				break;
			}
			parsed_args->flags |= SETGRP_FLAG;
			break;

		/* Take -y as confirmation and don't ask (where applicable). */
		case 'y':
			confirm = B_TRUE;
			break;

		/* Option without operand. */
		case ':':
			switch (optopt) {
			case 'p':
				/* Allow -p without bdf spec. */
				parsed_args->flags |=
				    (PROBETREE_FLAG | PROBERNG_FLAG);
				break;
			default:
				error = B_TRUE;
				break;
			}
			break;

		/* Unrecognized option. */
		case '?':
			error = B_TRUE;
			break;
		}
	}

	/*
	 * Commandline has been parsed.  Check for errors which can be checked
	 * only after commandline parsing is complete.
	 */

	if (!error) {

		/* Check for values straggling at the end of the command. */
		if (optind != argc) {
			(void) fprintf(stderr, "%s: Unrecognized parameter "
			    "at the end of the command.\n", argv[0]);
			print_bad_option(argv, optopt, optarg);
			return (FAILURE);
		}

		/* No args other than nexus.  Default to probing that nexus */
		if (!(parsed_args->flags &
		    (LEAF_FLAG | NEXUS_FLAG | INTR_FLAG | PROBE_FLAGS))) {
			usage(argv[0]);
			parsed_args->flags = 0;
			return (SUCCESS);
		}

		/*
		 * Don't allow any options other than all-bus, verbose or
		 * quiet with probe command.  Set default probe flags if nexus
		 * or leaf options are not specified.
		 */
		if (parsed_args->flags & (PROBETREE_FLAG | PROBEALL_FLAG)) {
			if (parsed_args->flags &
			    ~(PROBE_FLAGS | QUIET_FLAG | VERBOSE_FLAG))
				error = B_TRUE;
		}

		/*
		 * Allow only read, write, quiet and verbose flags for
		 * interrupt command.  Note that INO_SPEC_FLAG and CPU_SPEC_FLAG
		 * get set for interrupt command.
		 */
		if (parsed_args->flags & INTR_FLAG) {
			if (parsed_args->flags &
			    ~(INTR_FLAG | VERBOSE_FLAG | QUIET_FLAG |
			    READ_FLAG | WRITE_FLAG | SHOWCTLR_FLAG |
			    SETGRP_FLAG | INO_ALL_FLAG | INO_SPEC_FLAG |
			    MSI_ALL_FLAG | MSI_SPEC_FLAG | CPU_SPEC_FLAG)) {
				(void) fprintf(stderr, "%s: -v, -q, -r, -w, -c "
				    "-g are only options allowed with "
				    "interrupt command.\n", argv[0]);
				error = B_TRUE;
			}

			/* Need cpu and ino values for interrupt set command. */
			if ((parsed_args->flags & WRITE_FLAG) &&
			    !(parsed_args->flags & CPU_SPEC_FLAG) &&
			    !((parsed_args->flags & INO_SPEC_FLAG) ||
			    (parsed_args->flags & MSI_SPEC_FLAG))) {
				(void) fprintf(stderr,
				    "%s: Both cpu and ino/msi must be "
				    "specified explicitly for interrupt "
				    "set command.\n", argv[0]);
				error = B_TRUE;
			}

			/* Intr write and show ctlr flags are incompatible. */
			if ((parsed_args->flags &
			    (WRITE_FLAG + SHOWCTLR_FLAG)) ==
			    (WRITE_FLAG + SHOWCTLR_FLAG)) {
				(void) fprintf(stderr,
				    "%s: -w and -c are incompatible for "
				    "interrupt command.\n", argv[0]);
				error = B_TRUE;
			}

			/* Intr setgrp flag valid only for intr writes. */
			if ((parsed_args->flags & (WRITE_FLAG + SETGRP_FLAG)) ==
			    SETGRP_FLAG) {
				(void) fprintf(stderr,
				    "%s: -g is incompatible with -r "
				    "for interrupt command.\n", argv[0]);
				error = B_TRUE;
			}

			/*
			 * Disallow read & write together in interrupt command.
			 */
			if ((parsed_args->flags & (WRITE_FLAG | READ_FLAG)) ==
			    (WRITE_FLAG | READ_FLAG)) {
				(void) fprintf(stderr, "%s: Only one of -r and "
				    "-w can be specified in "
				    "interrupt command.\n", argv[0]);
				error = B_TRUE;
			}
		}

		/* Bytedump incompatible with some other options. */
		if ((parsed_args->flags & BYTEDUMP_FLAG) &&
		    (parsed_args->flags &
		    (WRITE_FLAG | PROBE_FLAGS | INTR_FLAG))) {
			(void) fprintf(stderr,
			    "%s: -b is incompatible with "
			    "another specified option.\n", argv[0]);
			error = B_TRUE;
		}

		if (parsed_args->flags & (LEAF_FLAG | NEXUS_FLAG)) {

			if (!(parsed_args->flags & SIZE_FLAG)) {
				parsed_args->size = DEFAULT_SIZE;
			}
			if ((parsed_args->flags & WRITE_FLAG) &&
			    parsed_args->size < sizeof (uint64_t) &&
			    (parsed_args->write_value >>
			    (parsed_args->size * BITS_PER_BYTE))) {
				(void) fprintf(stderr,
				    "%s: Data to write is larger than "
				    "specified size.\n", argv[0]);
				error = B_TRUE;
			}

		} else { /* Looping is compatible only with register cmds. */

			if (parsed_args->flags & LOOP_FLAG) {
				(void) fprintf(stderr, "%s: -l is incompatible "
				    "with given command.\n", argv[0]);
				error = B_TRUE;
			}
		}

		/* Call out an erroneous -y and then ignore it. */
		if ((confirm) && (!(parsed_args->flags & BASE_SPEC_FLAG))) {
				(void) fprintf(stderr,
				    "%s: -y is incompatible with given command."
				    "  Ignoring.\n", argv[0]);
		}
	}

	/* Now fill in the defaults and other holes. */
	if (!(error)) {
		if (!(parsed_args->flags & (READ_FLAG | WRITE_FLAG))) {
			parsed_args->flags |= READ_FLAG;
		}

		if (parsed_args->flags & (LEAF_FLAG | NEXUS_FLAG)) {
			if (!(parsed_args->flags & ENDIAN_FLAG)) {
				parsed_args->big_endian = B_FALSE;
			}
		}

		if (parsed_args->flags & BASE_SPEC_FLAG) {
			if (!confirm) {
				confirm = get_confirmation();
			}
			if (!confirm) {
				parsed_args->flags &= ~ALL_COMMANDS;
			}
		}

		/*
		 * As far as other defaults are concerned:
		 *   Other fields: bus, device, function, offset, default to
		 *   zero.
		 */

	} else {	/* An error occurred. */

		print_bad_option(argv, optopt, optarg);
	}
	return (error);
}


/* Module-private functions. */

static void
print_bad_option(char *argv[], int optopt, char *optarg)
{
	/* Illegal option operand */
	if (optarg != NULL) {
		(void) fprintf(stderr,
		    "%s: illegal operand %s specified for option %c\n",
		    argv[0], optarg, optopt);

	/* Illegal option */
	} else if (optopt != 0) {
		(void) fprintf(stderr,
		    "%s: option %c is illegal or is missing an operand\n",
		    argv[0], optopt);

	/* getopt wasn't even called.  Bad device spec. */
	} else {
		(void) fprintf(stderr,
		    "%s: device spec must start with %s or %s...\n", argv[0],
		    DEVNAME_START_PCI, DEVNAME_START_NIU);
	}

	(void) fprintf(stderr,
	    "%s: Type \"%s -h\" to get help on running this program.\n",
	    argv[0], argv[0]);
}

/*
 * Warn the user and ask for confirmation.
 */
static boolean_t
get_confirmation()
{
	int i, b;

	(void) printf("WARNING: This cmd with a bad addr can panic "
	    "the system.  Continue [y/n] (n)? ");
	for (i = 0; ; i++) {
		b = getchar();
		switch (b) {
		case ' ':
		case '\t':
			break;
		case 'y':
		case 'Y':
			return (B_TRUE);
		default:
			return (B_FALSE);
		}
	}
}


/*
 * Given a digit string, return a 64 bit value.
 *
 * If the hex_only arg is true, interpret all strings as hex.
 * Otherwise, interpret as strtoull(3C) does with base=0.
 */
static int
get_value64(char *value_str, uint64_t *value, boolean_t hex_only)
{

	/* This is overkill for now, as everything is in hex. */
	static char dec_digits[] = "0123456789";
	static char hex_digits[] = "01234567890abcdefABCDEF";
	static char oct_digits[] = "01234567";

	char *digit_string;
	char *string_to_check;

	if ((value_str == NULL) || (strlen(value_str) == 0)) {
		(void) fprintf(stderr, "Missing value argument.\n");
		return (FAILURE);
	}

	if (!hex_only && (value_str[0] != '0')) {
		digit_string = dec_digits;
		string_to_check = value_str;
	} else if ((value_str[1] == 'X') || (value_str[1] == 'x')) {
		digit_string = hex_digits;
		string_to_check = &value_str[2];	/* Ignore 0x of hex */
	} else if (hex_only) {
		digit_string = hex_digits;
		string_to_check = value_str;	/* Hex number, no 0x prefix */
	} else {
		digit_string = oct_digits;
		string_to_check = value_str;
	}

	/*
	 * Verify value is all proper digits.
	 *
	 * For some reason, strtoull doesn't return an error when it cannot
	 * interpret the value.  This is why we do the checking ourselves.
	 */
	if (strspn(string_to_check, digit_string) != strlen(string_to_check)) {
		(void) fprintf(stderr,
		    "Value must contain only valid digits.\n");
		return (FAILURE);
	}

	*value = strtoull(value_str, NULL, (hex_only ? 16 : 0));

	return (SUCCESS);
}


/*
 * Parse nexus options.  This includes:
 *   bank=number
 *
 * input is what the user specified for the options on the commandline,
 * flags_arg is modified with the option set, and bank_arg returns the value
 * specified for bank.
 */
static int
parse_nexus_opts(char *input, uint64_t *flags_arg, uint8_t *bank_arg,
    uint64_t *base_addr_arg)
{
	enum nexus_opts_index {
		bank = 0,
		base
	};

	static char *nexus_opts[] = {
		"bank",
		"base",
		NULL
	};

	char *value;
	uint64_t	recv64;

	int rval = SUCCESS;

	if (input == NULL) {
		(void) fprintf(stderr, "Missing argument.\n");
		return (FAILURE);
	}

	while ((*input != '\0') && (rval == SUCCESS)) {
		switch (getsubopt(&input, nexus_opts, &value)) {
		case bank:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, "The bank or bar arg is "
				    "specified more than once.\n");
				rval = FAILURE;
				break;
			}
			if (*flags_arg & BASE_SPEC_FLAG) {
				(void) fprintf(stderr, "Bank and base address "
				    "cannot both be specified.\n");
				rval = FAILURE;
				break;
			}
			if (value == NULL) {
				(void) fprintf(stderr, "Missing bank value.\n");
				rval = FAILURE;
				break;
			}
			if ((rval = get_value64(value, &recv64, HEX_ONLY)) !=
			    SUCCESS) {
				break;
			}
			*bank_arg = (uint8_t)recv64;
			if (*bank_arg != recv64) {
				(void) fprintf(stderr,
				    "Bank argument must fit into 8 bits.\n");
				rval = FAILURE;
				break;
			}
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		case base:
			if (*flags_arg & BASE_SPEC_FLAG) {
				(void) fprintf(stderr, "The base address "
				    "is specified more than once.\n");
				rval = FAILURE;
				break;
			}
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, "Bank and base address "
				    "cannot both be specified.\n");
				rval = FAILURE;
				break;
			}
			if (value == NULL) {
				(void) fprintf(stderr,
				    "Missing base addr value.\n");
				rval = FAILURE;
				break;
			}
			if ((rval = get_value64(value, base_addr_arg,
			    HEX_ONLY)) != SUCCESS) {
				break;
			}
			*flags_arg |= BASE_SPEC_FLAG;
			break;

		default:
			(void) fprintf(stderr, "Unrecognized option for -n\n");
			rval = FAILURE;
			break;
		}
	}

	return (rval);
}


static int
extract_bdf_arg(char *cvalue, char *fld, uint64_t fld_flag, uint64_t *all_flags,
    uint8_t *ivalue)
{
	uint64_t recv64;

	if (*all_flags & fld_flag) {
		(void) fprintf(stderr,
		    "The %s is specified more than once.\n", fld);
		return (FAILURE);
	}
	if (get_value64(cvalue, &recv64, HEX_ONLY) != SUCCESS)
		return (FAILURE);

	*ivalue = (uint8_t)recv64;
	if (recv64 != *ivalue) {
		(void) fprintf(stderr,
		    "This program limits the %s argument to 8 bits.\n", fld);
		(void) fprintf(stderr, "The actual maximum may be "
		    "smaller but cannot be enforced by this program.\n");
		return (FAILURE);
	}

	*all_flags |= fld_flag;
	return (SUCCESS);
}


static int extract_bdf(char *value, char **bvalue_p, char **dvalue_p,
    char **fvalue_p)
{
	char *strtok_state;
	char *dummy;
	static char *separator = ".";

	*bvalue_p = strtok_r(value, separator, &strtok_state);
	*dvalue_p = strtok_r(NULL, separator, &strtok_state);
	*fvalue_p = strtok_r(NULL, separator, &strtok_state);
	dummy = strtok_r(NULL, separator, &strtok_state);

	/* Return failure only if too many values specified. */
	return ((dummy) ? FAILURE : SUCCESS);
}

/*
 * Parse device options.  This includes:
 *   bus=number
 *   dev=number
 *   func=number
 *   bank=number
 *   config
 *   bar0
 *   bar1
 *   bar2
 *   bar3
 *   bar4
 *   bar5
 *   rom
 *
 * input is what the user specified for the options on the commandline,
 * flags_arg is modified with the options set, and the rest of the args return
 * their respective values.
 */
static int
parse_device_opts(
    char *input, uint64_t *flags_arg, uint8_t *bus_arg, uint8_t *device_arg,
    uint8_t *func_arg, uint8_t *bank_arg)
{
	/* Needed by getsubopt(3C) */
	enum bdf_opts_index {
		bus = 0,
		dev = 1,
		func = 2,
		bdf = 3,
		bank = 4,
		config = 5,
		bar0 = 6,
		bar1 = 7,
		bar2 = 8,
		bar3 = 9,
		bar4 = 10,
		bar5 = 11,
		rom = 12
	};

	/* Needed by getsubopt(3C) */
	static char *bdf_opts[] = {
		"bus",
		"dev",
		"func",
		"bdf",
		"bank",
		"config",
		"bar0",
		"bar1",
		"bar2",
		"bar3",
		"bar4",
		"bar5",
		"rom",
		NULL };

	char *value;		/* Current suboption being processed. */
	uint64_t recv64;	/* Temporary value. */

	/* This error message is used in many places. */
	static char bank_err[] =
	    {"The bank or bar arg is specified more than once.\n"};

	int rval = SUCCESS;

	while ((*input != '\0') && (rval == SUCCESS)) {
		switch (getsubopt(&input, bdf_opts, &value)) {

		/* bus=number */
		case bdf: {
			char *bvalue, *dvalue, *fvalue;

			if ((rval = extract_bdf(value, &bvalue, &dvalue,
			    &fvalue)) != SUCCESS) {
				break;
			}

			if (!bvalue | !dvalue | !fvalue) {
				break;
			}

			if ((rval = extract_bdf_arg(bvalue, "bus",
			    BUS_SPEC_FLAG, flags_arg, bus_arg)) != SUCCESS) {
				break;
			}
			if ((rval = extract_bdf_arg(dvalue, "dev",
			    DEV_SPEC_FLAG, flags_arg, device_arg)) != SUCCESS) {
				break;
			}
			rval = extract_bdf_arg(fvalue, "func",
			    FUNC_SPEC_FLAG, flags_arg, func_arg);
			break;
		}

		case bus:
			rval = extract_bdf_arg(value, "bus", BUS_SPEC_FLAG,
			    flags_arg, bus_arg);
			break;

		/* dev=number */
		case dev:
			rval = extract_bdf_arg(value, "dev", DEV_SPEC_FLAG,
			    flags_arg, device_arg);
			break;

		/* func=number */
		case func:
			rval = extract_bdf_arg(value, "func", FUNC_SPEC_FLAG,
			    flags_arg, func_arg);
			break;

		/* bank=number */
		case bank:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			if ((rval = get_value64(value, &recv64, HEX_ONLY)) !=
			    SUCCESS) {
				break;
			}
			*bank_arg = (uint8_t)recv64;
			if (rval || (*bank_arg != recv64)) {
				(void) fprintf(stderr, "Bank argument must"
				    " fit into 8 bits.\n");
				rval = FAILURE;
				break;
			}
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* config */
		case config:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_CONFIG;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* bar0 */
		case bar0:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_BAR0;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* bar1 */
		case bar1:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_BAR1;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* bar2 */
		case bar2:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_BAR2;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* bar3 */
		case bar3:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_BAR3;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* bar4 */
		case bar4:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_BAR4;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* bar5 */
		case bar5:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_BAR5;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		/* rom */
		case rom:
			if (*flags_arg & BANK_SPEC_FLAG) {
				(void) fprintf(stderr, bank_err);
				rval = FAILURE;
				break;
			}
			*bank_arg = PCITOOL_ROM;
			*flags_arg |= BANK_SPEC_FLAG;
			break;

		default:
			(void) fprintf(stderr, "Unrecognized option for -d\n");
			rval = FAILURE;
			break;
		}
	}

	/* Bus, dev and func must all be specified. */
	if ((*flags_arg & (BUS_SPEC_FLAG | DEV_SPEC_FLAG | FUNC_SPEC_FLAG)) !=
	    (BUS_SPEC_FLAG | DEV_SPEC_FLAG | FUNC_SPEC_FLAG)) {
		rval = FAILURE;

	/* No bank specified in any way.  Default to config space */
	} else if ((*flags_arg & BANK_SPEC_FLAG) == 0) {
		*flags_arg |= BANK_SPEC_FLAG;
		*bank_arg = PCITOOL_CONFIG;
	}

	return (rval);
}


/*
 * Parse INO options.  This includes:
 *   ino#  | all
 *
 * input is the string of options to parse.  flags_arg returns modified with
 * specified options set.  Other args return their respective values.
 */
static int
parse_ino_opts(char *input, uint64_t *flags_arg, uint32_t *cpu_arg,
    uint8_t *ino_arg)
{
	uint64_t	value;
	char		*charvalue;
	int		rval = SUCCESS;

	if (strcmp(input, "all") == 0) {
		*flags_arg |= INO_ALL_FLAG;
#ifdef __x86
	} else if (strstr(input, ",") == NULL) {
		(void) fprintf(stderr,
		    "Interrupt format should be <cpu#,ino#>.\n");
		rval = FAILURE;
#else
	} else if (strstr(input, ",") == NULL) {
		if ((rval = get_value64(input, &value, HEX_ONLY)) == SUCCESS)
			*ino_arg = (uint8_t)value;

		if (*ino_arg != value) {
			(void) fprintf(stderr,
			    "ino argument must fit into 8 bits.\n");
			rval = FAILURE;
		} else {
			*flags_arg |= INO_SPEC_FLAG;
		}
#endif
	} else if (charvalue = strtok(input, ",")) {
		if ((rval =
		    get_value64(charvalue, &value, HEX_ONLY)) == SUCCESS) {
			*cpu_arg = (int)value;
		}

		input = strtok(NULL, ",");
		if (input == NULL) {
			(void) fprintf(stderr, "ino argument is need.\n");
			return (FAILURE);
		}

		if ((rval = get_value64(input, &value, HEX_ONLY)) == SUCCESS)
			*ino_arg = (uint8_t)value;

		if (*ino_arg != value) {
			(void) fprintf(stderr,
			    "ino argument must fit into 8 bits.\n");
			rval = FAILURE;
		} else {
			*flags_arg |= INO_SPEC_FLAG;
		}
	} else {
		(void) fprintf(stderr,
		    "Unrecognized option for -i\n");
		rval = FAILURE;
	}

	return (rval);
}


/*
 * Parse MSI options.  This includes:
 *   msi#  | all
 *
 * input is the string of options to parse.  flags_arg returns modified with
 * specified options set.  Other args return their respective values.
 */
static int
parse_msi_opts(char *input, uint64_t *flags_arg, uint16_t *msi_arg)
{
	uint64_t	value;
	int		rval = SUCCESS;

	if (strcmp(input, "all") == 0) {
		*flags_arg |= MSI_ALL_FLAG;
	} else if (strstr(input, ",") == NULL) {
		if ((rval = get_value64(input, &value, HEX_ONLY)) == SUCCESS)
			*msi_arg = (uint16_t)value;

		if (*msi_arg != value) {
			(void) fprintf(stderr,
			    "msi argument must fit into 16 bits.\n");
			rval = FAILURE;
		} else {
			*flags_arg |= MSI_SPEC_FLAG;
		}
	} else if (strtok(input, ",")) {
		input = strtok(NULL, ",");
		if (input == NULL) {
			(void) fprintf(stderr, "msi argument is need.\n");
			return (FAILURE);
		}

		if ((rval = get_value64(input, &value, HEX_ONLY)) == SUCCESS)
			*msi_arg = (uint16_t)value;

		if (*msi_arg != value) {
			(void) fprintf(stderr,
			    "msi argument must fit into 16 bits.\n");
			rval = FAILURE;
		} else {
			*flags_arg |= MSI_SPEC_FLAG;
		}
	} else {
		(void) fprintf(stderr,
		    "Unrecognized option for -m\n");
		rval = FAILURE;
	}

	return (rval);
}


/*
 * Parse interrupt set options.  This includes:
 *   cpu=number
 *
 * input is the string of options to parse.  flags_arg returns modified with
 * specified options set.  Other args return their respective values.
 */
static int
parse_intr_set_opts(char *input, uint64_t *flags_arg, uint32_t *cpu_arg)
{
	uint64_t	value;
	int		rval = SUCCESS;

	if ((rval = get_value64(input, &value, HEX_ONLY)) == SUCCESS) {

		if ((long)value > sysconf(_SC_CPUID_MAX)) {
			(void) fprintf(stderr, "Cpu argument "
			    "exceeds maximum for this system type.\n");
			rval = FAILURE;
		} else {
			*cpu_arg = (uint32_t)value;
			*flags_arg |= CPU_SPEC_FLAG;
		}
	} else {
		(void) fprintf(stderr,
		    "Unrecognized option for -i -m -w\n");
			rval = FAILURE;
	}

	return (rval);
}


static int
parse_probeone_opts(
    char *input, uint64_t *flags_arg, uint8_t *bus_arg, uint8_t *device_arg,
    uint8_t *func_arg)
{
	enum p1_bdf_opts_index {
		bus = 0,
		dev = 1,
		func = 2,
		bdf = 3
	};

	/* Needed by getsubopt(3C) */
	static char *p1_bdf_opts[] = {
		"bus",
		"dev",
		"func",
		"bdf",
		NULL };

	char *value;		/* Current suboption being processed. */

	int rval = SUCCESS;

	while ((*input != '\0') && (rval == SUCCESS)) {
		switch (getsubopt(&input, p1_bdf_opts, &value)) {

		/* bus=number */
		case bdf: {
			char *bvalue, *dvalue, *fvalue;

			if ((rval = extract_bdf(value, &bvalue, &dvalue,
			    &fvalue)) != SUCCESS) {
				break;
			}
			if (bvalue)
				if ((rval = extract_bdf_arg(bvalue, "bus",
				    BUS_SPEC_FLAG, flags_arg, bus_arg)) !=
				    SUCCESS) {
					break;
				}
			if (dvalue)
				if ((rval = extract_bdf_arg(dvalue, "dev",
				    DEV_SPEC_FLAG, flags_arg, device_arg)) !=
				    SUCCESS) {
				break;
			}
			if (fvalue)
				rval = extract_bdf_arg(fvalue, "func",
				    FUNC_SPEC_FLAG, flags_arg, func_arg);
			break;
		}

		case bus:
			rval = extract_bdf_arg(value, "bus", BUS_SPEC_FLAG,
			    flags_arg, bus_arg);
			break;

		/* dev=number */
		case dev:
			rval = extract_bdf_arg(value, "dev", DEV_SPEC_FLAG,
			    flags_arg, device_arg);
			break;

		/* func=number */
		case func:
			rval = extract_bdf_arg(value, "func", FUNC_SPEC_FLAG,
			    flags_arg, func_arg);
			break;

		default:
			(void) fprintf(stderr, "Unrecognized option for -p\n");
			rval = FAILURE;
			break;
		}
	}

	return (rval);
}


#ifdef DEBUG

static void
dump_struct(pcitool_uiargs_t *dumpthis)
{
	(void) printf("flags:0x%x\n", dumpthis->flags);
	(void) printf("bus:%d (0x%x)\n",
	    dumpthis->bus, dumpthis->bus);
	(void) printf("device:%d (0x%x)\n", dumpthis->device,
	    dumpthis->device);
	(void) printf("function:%d (0x%x)\n", dumpthis->function,
	    dumpthis->function);
	(void) printf("write_value:%" PRIu64 " (0x%" PRIx64 ")\n",
	    dumpthis->write_value, dumpthis->write_value);
	(void) printf("bank:%d (0x%x)\n",
	    dumpthis->bank, dumpthis->bank);
	(void) printf("offset:%d (0x%x)\n", dumpthis->offset, dumpthis->offset);
	(void) printf("size:%d, endian:%s\n", dumpthis->size,
	    dumpthis->big_endian ? "BIG" : "little");
	(void) printf("ino:%d, cpu:%d\n",
	    dumpthis->intr_ino, dumpthis->intr_cpu);
}

#ifdef STANDALONE

/* Test program for this module.  Useful when implementing new options. */
int
main(int argc, char *argv[])
{
	int status;
	pcitool_uiargs_t parsed_args;

	status = get_commandline_args(argc, argv, &parsed_args);
	if (status) {
		(void) printf("Error getting command.\n");
	}
	dump_struct(&parsed_args);

	return (SUCCESS);
}

#endif	/* STANDALONE */
#endif	/* DEBUG */
