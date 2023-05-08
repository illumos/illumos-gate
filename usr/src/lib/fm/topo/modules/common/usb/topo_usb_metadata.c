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
 * This module parses the private file format used for describing
 * platform-specific USB overrides.
 *
 * FILE FORMAT
 * -----------
 *
 * A USB topology file contains a series of lines which are separated by new
 * lines. Leading and trailing whitespace on a line are ignored and empty lines
 * are ignored as well. The '#' character is used as a comment character. There
 * are a series of keywords that are supported which are used to indicate
 * different control aspects. These keywords are all treated in a
 * case-insensitive fashion. There are both top-level keywords and keywords that
 * are only accepted within the context of a scope.
 *
 * Top-level keywords
 * ------------------
 *
 * The following keywords are accepted, but must not be found inside a nested
 * scope:
 *
 *   'disable-acpi'		Disables the use of ACPI for this platform. This
 *				includes getting information about the port's
 *				type and visibility. This implies
 *				'disable-acpi-match'.
 *
 *   'disable-acpi-match'	Disables the act of trying to match ports based
 *				on ACPI.
 *
 *
 *   'enable-acpi-match'	Explicitly enables ACPI port matching on the
 *				platform based on ACPI.
 *
 *   'enable-metadata-match'	Enables port matching based on metadata. This is
 *				most commonly used on platforms that have ehci
 *				and xhci controllers that share ports.
 *
 *   'port'			Begins a port stanza that describes a single
 *				physical port. This stanza will continue until
 *				the 'end-port' keyword is encountered.
 *
 * Port Keywords
 * -------------
 *
 * Some port keywords take arguments and others do not. When an argument exists,
 * will occur on the subsequent line. Ports have a series of directives that
 * describe metadata as well as directives that describe how to determine the
 * port.
 *
 *   'label'			Indicates that the next line contains the
 *				human-readable label for the port.
 *
 *   'chassis'			Indicates that this port is part of the chassis
 *				and should not be enumerated elsewhere.
 *
 *   'external'			Indicates that this port is externally visible.
 *
 *   'internal'			Indicates that this port is internal to the
 *				chassis and cannot be accessed without opening
 *				the chassis.
 *
 *   'port-type'		Indicates that the next line contains a number
 *				which corresponds to the type of the port. The
 *				port numbers are based on the ACPI table and
 *				may be in either base 10 or hexadecimal.
 *
 *   'acpi-path'		Indicates that the next line contains an ACPI
 *				based name that matches the port.
 *
 *   'end-port'			Closes the port-clause.
 */

#include <libnvpair.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fm/topo_list.h>
#include <fm/topo_mod.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>
#include <sys/debug.h>
#include <ctype.h>
#include <unistd.h>

#include "topo_usb.h"
#include "topo_usb_int.h"

/*
 * Maximum number of characters we expect to encounter in a line.
 */
#define	TOPO_USB_META_LINE_MAX	1000

/*
 * This constant is the default set of flags that we'd like to apply when there
 * is no configuration file present to determine the desired behavior. If one is
 * present, we always defer to what it asks for.
 *
 * It's a difficult decision to enable ACPI by default or not. Unfortunately,
 * we've encountered some systems where the ACPI information is wrong. However,
 * we've encountered a larger number where it is correct. When it's correct,
 * this greatly simplifies some of the work that we have to do. Our default
 * disposition at the moment is to opt to decide its correct as that ends up
 * giving us much better information.
 */
#define	USB_TOPO_META_DEFAULT_FLAGS	TOPO_USB_M_ACPI_MATCH

typedef enum {
	TOPO_USB_P_START,
	TOPO_USB_P_PORT,
	TOPO_USB_P_LABEL,
	TOPO_USB_P_PORT_TYPE,
	TOPO_USB_P_ACPI_PATH
} topo_usb_parse_state_t;

typedef struct topo_usb_parse {
	topo_usb_parse_state_t	tp_state;
	topo_list_t		*tp_ports;
	topo_usb_meta_port_t	*tp_cport;
	topo_usb_meta_flags_t	tp_flags;
} topo_usb_parse_t;

/*
 * Read the next line in the file with content. Trim trailing and leading
 * whitespace and trim comments out. If this results in an empty line, read the
 * next. Returns zero if we hit EOF. Otherwise, returns one if data, or negative
 * one if an error occurred.
 */
static int
topo_usb_getline(topo_mod_t *mod, char *buf, size_t len, FILE *f, char **first)
{
	while (fgets(buf, len, f) != NULL) {
		char *c;
		size_t i;

		if ((c = strrchr(buf, '\n')) == NULL) {
			topo_mod_dprintf(mod, "failed to find new line in "
			    "metadata file");
			return (-1);
		}

		while (isspace(*c) != 0 && c >= buf) {
			*c = '\0';
			c--;
			continue;
		}

		if ((c = strchr(buf, '#')) != 0) {
			*c = '\0';
		}

		for (i = 0; buf[i] != '\0'; i++) {
			if (isspace(buf[i]) == 0)
				break;
		}

		if (buf[i] == '\0')
			continue;
		*first = &buf[i];
		return (1);
	}

	return (0);
}

static boolean_t
topo_usb_parse_start(topo_mod_t *mod, topo_usb_parse_t *parse, const char *line)
{
	topo_usb_meta_port_t *port;

	VERIFY3S(parse->tp_state, ==, TOPO_USB_P_START);
	VERIFY3P(parse->tp_cport, ==, NULL);

	if (strcasecmp(line, "disable-acpi") == 0) {
		parse->tp_flags |= TOPO_USB_M_NO_ACPI;
		parse->tp_flags &= ~TOPO_USB_M_ACPI_MATCH;
		return (B_TRUE);
	} else if (strcasecmp(line, "disable-acpi-match") == 0) {
		parse->tp_flags &= ~TOPO_USB_M_ACPI_MATCH;
		return (B_TRUE);
	} else if (strcasecmp(line, "enable-acpi-match") == 0) {
		parse->tp_flags |= TOPO_USB_M_ACPI_MATCH;
		return (B_TRUE);
	} else if (strcasecmp(line, "enable-metadata-match") == 0) {
		parse->tp_flags |= TOPO_USB_M_METADATA_MATCH;
		return (B_TRUE);
	} else if (strcasecmp(line, "port") != 0) {
		topo_mod_dprintf(mod, "expected 'port', encountered %s",
		    line);
		return (B_FALSE);
	}

	if ((port = topo_mod_zalloc(mod, sizeof (topo_usb_meta_port_t))) ==
	    NULL) {
		topo_mod_dprintf(mod, "failed to allocate metadata port");
		return (B_FALSE);
	}
	port->tmp_port_type = 0xff;

	parse->tp_cport = port;
	parse->tp_state = TOPO_USB_P_PORT;
	return (B_TRUE);
}

static boolean_t
topo_usb_parse_port(topo_mod_t *mod, topo_usb_parse_t *parse, const char *line)
{
	VERIFY3S(parse->tp_state, ==, TOPO_USB_P_PORT);
	VERIFY3P(parse->tp_cport, !=, NULL);

	if (strcasecmp(line, "label") == 0) {
		parse->tp_state = TOPO_USB_P_LABEL;
	} else if (strcasecmp(line, "chassis") == 0) {
		parse->tp_cport->tmp_flags |= TOPO_USB_F_CHASSIS;
	} else if (strcasecmp(line, "external") == 0) {
		parse->tp_cport->tmp_flags |= TOPO_USB_F_EXTERNAL;
	} else if (strcasecmp(line, "internal") == 0) {
		parse->tp_cport->tmp_flags |= TOPO_USB_F_INTERNAL;
	} else if (strcasecmp(line, "port-type") == 0) {
		parse->tp_state = TOPO_USB_P_PORT_TYPE;
	} else if (strcasecmp(line, "acpi-path") == 0) {
		parse->tp_state = TOPO_USB_P_ACPI_PATH;
	} else if (strcasecmp(line, "end-port") == 0) {
		topo_list_append(parse->tp_ports, parse->tp_cport);
		parse->tp_cport = NULL;
		parse->tp_state = TOPO_USB_P_START;
	} else {
		topo_mod_dprintf(mod, "illegal directive in port block: %s",
		    line);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
topo_usb_parse_label(topo_mod_t *mod, topo_usb_parse_t *parse, const char *line)
{
	size_t i, len;

	VERIFY3S(parse->tp_state, ==, TOPO_USB_P_LABEL);

	len = strlen(line);
	for (i = 0; i < len; i++) {
		if (isascii(line[i]) == 0 || isprint(line[i]) == 0) {
			topo_mod_dprintf(mod, "label character %zu is "
			    "invalid: 0x%x", i, line[i]);
			return (B_FALSE);
		}
	}

	if (parse->tp_cport->tmp_label != NULL) {
		topo_mod_strfree(mod, parse->tp_cport->tmp_label);
	}

	if ((parse->tp_cport->tmp_label = topo_mod_strdup(mod, line)) == NULL) {
		topo_mod_dprintf(mod, "failed to duplicate label for port");
		return (B_FALSE);
	}

	parse->tp_state = TOPO_USB_P_PORT;

	return (B_TRUE);
}

static boolean_t
topo_usb_parse_port_type(topo_mod_t *mod, topo_usb_parse_t *parse,
    const char *line)
{
	unsigned long val;
	char *eptr;

	VERIFY3S(parse->tp_state, ==, TOPO_USB_P_PORT_TYPE);

	errno = 0;
	val = strtoul(line, &eptr, 0);
	if (errno != 0 || *eptr != '\0' || val >= UINT_MAX) {
		topo_mod_dprintf(mod, "encountered bad value for port-type "
		    "line: %s", line);
		return (B_FALSE);
	}

	parse->tp_cport->tmp_port_type = (uint_t)val;

	parse->tp_state = TOPO_USB_P_PORT;
	return (B_TRUE);
}

static boolean_t
topo_usb_parse_path(topo_mod_t *mod, topo_usb_parse_t *parse,
    topo_usb_path_type_t ptype, const char *line)
{
	char *fspath;
	topo_usb_meta_port_path_t *path;

	VERIFY(parse->tp_state == TOPO_USB_P_ACPI_PATH);
	VERIFY3P(parse->tp_cport, !=, NULL);

	if ((fspath = topo_mod_strdup(mod, line)) == NULL) {
		topo_mod_dprintf(mod, "failed to duplicate path");
		return (B_FALSE);
	}

	if ((path = topo_mod_zalloc(mod, sizeof (topo_usb_meta_port_path_t))) ==
	    NULL) {
		topo_mod_dprintf(mod, "failed to allocate meta port path "
		    "structure");
		topo_mod_strfree(mod, fspath);
		return (B_FALSE);
	}

	path->tmpp_type = ptype;
	path->tmpp_path = fspath;

	topo_list_append(&parse->tp_cport->tmp_paths, path);

	parse->tp_state = TOPO_USB_P_PORT;
	return (B_TRUE);
}


void
topo_usb_free_metadata(topo_mod_t *mod, topo_list_t *metadata)
{
	topo_usb_meta_port_t *mp;

	while ((mp = topo_list_next(metadata)) != NULL) {
		topo_usb_meta_port_path_t *path;

		while ((path = topo_list_next((&mp->tmp_paths))) != NULL) {
			topo_list_delete(&mp->tmp_paths, path);
			topo_mod_strfree(mod, path->tmpp_path);
			topo_mod_free(mod, path,
			    sizeof (topo_usb_meta_port_path_t));
		}

		topo_list_delete(metadata, mp);
		topo_mod_strfree(mod, mp->tmp_label);
		topo_mod_free(mod, mp, sizeof (topo_usb_meta_port_t));
	}
}

int
topo_usb_load_metadata(topo_mod_t *mod, tnode_t *pnode, topo_list_t *list,
    topo_usb_meta_flags_t *flagsp)
{
	int fd;
	FILE *f = NULL;
	char buf[TOPO_USB_META_LINE_MAX], *first, *prod;
	int ret;
	topo_usb_parse_t parse;
	char pbuf[PATH_MAX];

	*flagsp = USB_TOPO_META_DEFAULT_FLAGS;

	/*
	 * If no product string, just leave it as is and don't attempt to get
	 * metadata.
	 */
	if ((topo_prop_get_string(pnode, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_PRODUCT, &prod, &ret)) != 0) {
		topo_mod_dprintf(mod, "skipping metadata load: failed to get "
		    "auth");
		return (0);
	}

	if (snprintf(pbuf, sizeof (pbuf), "maps/%s-usb.usbtopo", prod) >=
	    sizeof (pbuf)) {
		topo_mod_dprintf(mod, "skipping metadata load: product name "
		    "too long");
		topo_mod_strfree(mod, prod);
		return (0);
	}
	topo_mod_strfree(mod, prod);

	if ((fd = topo_mod_file_search(mod, pbuf, O_RDONLY)) < 0) {
		topo_mod_dprintf(mod, "skipping metadata load: couldn't find "
		    "%s", pbuf);
		return (0);
	}


	if ((f = fdopen(fd, "r")) == NULL) {
		topo_mod_dprintf(mod, "failed to fdopen metadata file %s: %s",
		    pbuf, strerror(errno));
		VERIFY0(close(fd));
		ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		goto err;
	}

	bzero(&parse, sizeof (parse));
	parse.tp_ports = list;
	parse.tp_state = TOPO_USB_P_START;

	while ((ret = topo_usb_getline(mod, buf, sizeof (buf), f, &first)) !=
	    0) {
		if (ret == -1) {
			ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			goto err;
		}

		switch (parse.tp_state) {
		case TOPO_USB_P_START:
			if (!topo_usb_parse_start(mod, &parse, first)) {
				ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
				goto err;
			}
			break;
		case TOPO_USB_P_PORT:
			if (!topo_usb_parse_port(mod, &parse, first)) {
				ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
				goto err;
			}
			break;
		case TOPO_USB_P_LABEL:
				if (!topo_usb_parse_label(mod, &parse, first)) {
				ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
				goto err;
			}
			break;
		case TOPO_USB_P_PORT_TYPE:
			if (!topo_usb_parse_port_type(mod, &parse, first)) {
				ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
				goto err;
			}
			break;

		case TOPO_USB_P_ACPI_PATH:
			if (!topo_usb_parse_path(mod, &parse, TOPO_USB_T_ACPI,
			    first)) {
				ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
				goto err;
			}
			break;
		}
	}

	if (parse.tp_state != TOPO_USB_P_START) {
		topo_mod_dprintf(mod, "metadata file didn't end in correct "
		    "state, failing");
		ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		goto err;
	}

	topo_mod_dprintf(mod, "successfully loaded metadata %s", pbuf);
	VERIFY0(fclose(f));
	*flagsp = parse.tp_flags;
	return (0);

err:
	if (f != NULL)
		VERIFY0(fclose(f));
	topo_usb_free_metadata(mod, list);
	return (ret);
}
