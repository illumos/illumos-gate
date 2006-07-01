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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <widec.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <libintl.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/iscsi_protocol.h>
#include <door.h>
#include <iscsi_door.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/mman.h>
#include <sys/filio.h>
#include <libxml/xmlreader.h>
#include <libscf.h>
#include <fcntl.h>

#include "local_types.h"
#include "cmdparse.h"
#include "utility.h"
#include "xml.h"
#include "helper.h"

extern char *cmdName;

#define	WAIT_FOR_SERVICE	15
#define	WAIT_FOR_DOOR		15
static char *service = "system/iscsitgt:default";
static stat_delta_t *stat_head;

static Boolean_t
is_online()
{
	char		*s;
	Boolean_t	rval = False;

	if ((s = smf_get_state(service)) != NULL) {
		if (strcmp(s, SCF_STATE_STRING_ONLINE) == 0)
			rval = True;
		free(s);
	}

	return (rval);
}

Boolean_t
check_and_online()
{
	int		i,
			fd;

	if (is_online() == False) {
		if (smf_enable_instance(service, 0) != 0) {
			return (False);
		}
		for (i = 0; i < WAIT_FOR_SERVICE; i++) {
			if (is_online() == True)
				break;
			(void) sleep(1);
		}
		if (i == WAIT_FOR_SERVICE) {
			return (False);
		}
	}

	for (i = 0; i < WAIT_FOR_DOOR; i++) {
		if ((fd = open(ISCSI_TARGET_MGMT_DOOR, 0)) >= 0) {
			(void) close(fd);
			return (True);
		}
		(void) sleep(1);
	}
	return (False);
}

/*
 * []----
 * | buffer_xml -- buffer incoming XML response until complete
 * |
 * | Incoming data from target may not be a complete XML message. So,
 * | we need to wait until we've got everything otherwise the XML routines
 * | will generate a parsing error for a short buffer.
 * []----
 */
Boolean_t
buffer_xml(char *s, char **storage, xml_node_t **np)
{
	xml_node_t		*node		= NULL;
	xmlTextReaderPtr	r;
	char			*p,
				*e,
				*end_tag,
				hold_ch;

	p = *storage;
	if (s != NULL) {
		if (p == NULL) {
			p = strdup(s);
		} else {
			p = realloc(p, strlen(p) + strlen(s) + 1);
			(void) strcat(p, s);
		}
	}
	if (p == NULL) {
		return (False);
	}

	if (*p != '<') {
		return (False);
	}

	if ((e = strchr(p, '>')) == NULL) {
		return (False);
	}

	/*
	 * The +3 is for the slash, closing tag character and null
	 * For example if p is pointing at a string which starts with
	 * "<foo>...."
	 * p will point at '<' and e will point at '>'. e - p is 4, yet
	 * the tag length is really 5 characters. We will need to create
	 * the end tag which also has a slash and NULL byte.
	 */
	if ((end_tag = malloc(e - p + 3)) == NULL) {
		return (False);
	}

	end_tag[0] = '<';
	end_tag[1] = '/';

	/*
	 * Copy in the tag value and the closing tag character '>'.
	 */
	bcopy(p + 1, &end_tag[2], e - p);

	/*
	 * Add the null byte
	 */
	end_tag[e - p + 2] = '\0';

	/*
	 * Do we have the closing string yet? If not, just return
	 */
	if ((e = strstr(p, end_tag)) == NULL) {
		*storage = p;
		return (False);
	}

	/*
	 * Move past the closing tag and free the end_tag memory
	 */
	e += strlen(end_tag);
	free(end_tag);

	/*
	 * NULL terminate the string and remember to save that character
	 * so that we can restore it later.
	 */
	hold_ch = *e;
	*e = '\0';

	if ((r = (xmlTextReaderPtr)xmlReaderForMemory(p, strlen(p), NULL,
			NULL, 0)) == NULL)
		return (False);

	while (xmlTextReaderRead(r) == 1) {
		if (xml_process_node(r, &node) == False)
			break;
	}

	*np = node;

	xmlFreeTextReader(r);

	*e = hold_ch;
	for (; isspace(*e); e++)
		;
	if (*e != '\0') {
		*storage = strdup(e);
	} else
		*storage = NULL;
	free(p);
	return (True);
}

xml_node_t *
send_data(char *hostname, char *first_str)
{
	struct sockaddr_in	sin;
	struct hostent		*hp;
	int			s,
				min,
				nmsgs,
				nbytes,
				error_num,
				port		= 3269;
	struct pollfd		fds[1];
	nfds_t			nfds		= 1;
	char			input[128],
				*storage	= NULL;
	xml_node_t		*node		= NULL;

	if (hostname != NULL) {
		if ((hp = getipnodebyname(hostname, AF_INET,
		    AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED,
		    &error_num)) == NULL) {
			(void) printf("Can't find IP addr for %s\n", hostname);
			exit(1);
		}

		bzero(&sin, sizeof (sin));
		sin.sin_family	= hp->h_addrtype;
		sin.sin_port	= ntohs(port);
		bcopy(hp->h_addr_list[0], &sin.sin_addr, hp->h_length);

		if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			(void) printf("Failed to open socket\n");
			exit(1);
		}

		if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
			(void) printf("Failed to connect\n");
			exit(1);
		}

		fds[0].fd	= s;
		fds[0].events	= POLLIN;
		fds[0].revents	= 0;

		if (write(s, first_str, strlen(first_str)) !=
		    strlen(first_str)) {
			perror("Failed to send request");
			exit(1);
		}
		while (poll(fds, nfds, -1) != -1) {
			if ((nmsgs = ioctl(s, FIONREAD, &nbytes)) < 0)
				exit(1);
			if ((nmsgs == 0) && (nbytes == 0))
				exit(1);
			min = MIN(nbytes, sizeof (input) - 1);
			if (read(s, input, min) != min)
				exit(1);
			input[min] = '\0';

			if (buffer_xml(input, &storage, &node) == True) {
				break;
			}
		}
	} else {
		door_arg_t		d;
		xmlTextReaderPtr	r;

		d.data_ptr	= first_str;
		d.data_size	= strlen(first_str) + 1;
		d.desc_ptr	= NULL;
		d.desc_num	= 0;
		d.rbuf		= NULL;
		d.rsize		= 0;

		if (((s = open(ISCSI_TARGET_MGMT_DOOR, 0)) < 0) ||
		    (door_call(s, &d) < 0)) {
			if (s != -1)
				(void) close(s);

			if (check_and_online() == False) {
				(void) fprintf(stderr,
				    "iscsitadm: SMF service unavailable\n");
				exit(1);
			}

			if ((s = open(ISCSI_TARGET_MGMT_DOOR, 0)) < 0) {
				(void) fprintf(stderr,
				    "iscsitadm: Failed to open iSCSI target"
				    " management door\n");
				exit(1);
			}
			if (door_call(s, &d) < 0) {
				perror("door_call");
				exit(1);
			}
		}

		if ((r = (xmlTextReaderPtr)xmlReaderForMemory(d.rbuf,
		    strlen(d.rbuf), NULL, NULL, 0)) == NULL) {
			perror("xmlReaderForMemory");
			exit(1);
		}
		while (xmlTextReaderRead(r) == 1)
			if (xml_process_node(r, &node) == False)
				break;
		xmlFreeTextReader(r);
		(void) munmap(d.rbuf, d.rsize);
	}
	(void) close(s);
	return (node);
}

/*
 * Retrieve CHAP secret from input
 */
int
getSecret(char *secret, int *secretLen, int minSecretLen, int maxSecretLen)
{
	char *chapSecret;

	/* XXX Should we prompt for hex or ascii printable input? */

	/* get password */
	chapSecret = getpassphrase(gettext("Enter secret:"));

	if (strlen(chapSecret) > maxSecretLen) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("secret too long"));
		    *secret = NULL;
		    return (1);
	}

	if (strlen(chapSecret) < minSecretLen) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
			gettext("secret too short"));
			*secret = NULL;
			return (1);
	}

	(void) strcpy(secret, chapSecret);

	chapSecret = getpassphrase(gettext("Re-enter secret:"));
	if (strcmp(secret, chapSecret) != 0) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("secret not changed"));
		*secret = NULL;
		return (1);
	}
	*secretLen = strlen(chapSecret);
	return (0);
}

void
iSCSINameCheckStatusDisplay(iSCSINameCheckStatusType status)
{
	switch (status) {
		case iSCSINameLenZero:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("empty iSCSI name."));
			break;
		case iSCSINameLenExceededMax:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("iSCSI name exceeded maximum length."));
			break;
		case iSCSINameUnknownType:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("unknown iSCSI name type."));
			break;
		case iSCSINameIqnFormatError:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("iqn formatting error."));
			break;
		case iSCSINameEUIFormatError:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("eui formatting error."));
			break;
	}
}

/*
 * This helper function could go into a utility module for general use.
 */
int
parseAddress(char *address_port_str,
    uint16_t defaultPort,
    char *address_str,
    size_t address_str_len,
    uint16_t *port,
    boolean_t *isIpv6)
{
	char port_str[64];
	int tmp_port;

	if (address_port_str[0] == '[') {
		/* IPv6 address */
		char *close_bracket_pos;
		close_bracket_pos = strchr(address_port_str, ']');
		if (!close_bracket_pos) {
			syslog(LOG_USER|LOG_DEBUG,
			    "IP address format error: %s\n", address_str);
			return (PARSE_ADDR_MISSING_CLOSING_BRACKET);
		}

		*close_bracket_pos = NULL;
		(void) strlcpy(address_str, &address_port_str[1],
		    address_str_len);

		/* Extract the port number */
		close_bracket_pos++;
		if (*close_bracket_pos == ':') {
			close_bracket_pos++;
			if (*close_bracket_pos != NULL) {
				(void) strlcpy(port_str, close_bracket_pos,
				    64);
				tmp_port = atoi(port_str);
				if (((tmp_port > 0) &&
					(tmp_port > USHRT_MAX)) ||
					(tmp_port < 0)) {
					/* Port number out of range */
					syslog(LOG_USER|LOG_DEBUG,
					    "Specified port out of range: %d",
					    tmp_port);
					return (PARSE_ADDR_PORT_OUT_OF_RANGE);
				} else {
					*port = (uint16_t)tmp_port;
				}
			} else {
				*port = defaultPort;
			}
		} else {
			*port = defaultPort;
		}

		*isIpv6 = B_TRUE;
	} else {
		/* IPv4 address */
		char *colon_pos;
		colon_pos = strchr(address_port_str, ':');
		if (!colon_pos) {
			/* No port number specified. */
			*port = defaultPort;
			(void) strlcpy(address_str, address_port_str,
			    address_str_len);
		} else {
			*colon_pos = (char)NULL;
			(void) strlcpy(address_str, address_port_str,
			    address_str_len);

			/* Extract the port number */
			colon_pos++;
			if (*colon_pos != NULL) {
				(void) strlcpy(port_str, colon_pos, 64);
				tmp_port = atoi(port_str);
				if (((tmp_port > 0) &&
					(tmp_port > USHRT_MAX)) ||
					(tmp_port < 0)) {
					/* Port number out of range */
					syslog(LOG_USER|LOG_DEBUG,
					    "Specified port out of range: %d",
					    tmp_port);
					return (PARSE_ADDR_PORT_OUT_OF_RANGE);
				} else {
					*port = (uint16_t)tmp_port;
				}
			} else {
				*port = defaultPort;
			}
		}

		*isIpv6 = B_FALSE;
	}

	return (PARSE_ADDR_OK);
}

/*
 * []----
 * | Following routine (number_to_scaled_string) is lifted
 * | from usr/src/cmd/fs.d/df.c
 * []----
 */
/*
 * Convert an unsigned long long to a string representation and place the
 * result in the caller-supplied buffer.
 * The given number is in units of "unit_from" size,
 * this will first be converted to a number in 1024 or 1000 byte size,
 * depending on the scaling factor.
 * Then the number is scaled down until it is small enough to be in a good
 * human readable format i.e. in the range 0 thru scale-1.
 * If it's smaller than 10 there's room enough to provide one decimal place.
 * The value "(unsigned long long)-1" is a special case and is always
 * converted to "-1".
 * Returns a pointer to the caller-supplied buffer.
 */
char *
number_to_scaled_string(
	char *buf,		/* put the result here */
	    unsigned long long number, /* convert this number */
	    int unit_from,
	    int scale)
{
	unsigned long long save = 0;
	char *M = "KMGTPE"; /* Measurement: kilo, mega, giga, tera, peta, exa */
	char *uom = M;    /* unit of measurement, initially 'K' (=M[0]) */

	if ((long long)number == (long long)-1) {
		(void) strcpy(buf, "-1");
		return (buf);
	}

	if ((number < scale) && (unit_from == 1)) {
		(void) sprintf(buf, "%4llu", number);
		return (buf);
	}
	/*
	 * Convert number from unit_from to given scale (1024 or 1000).
	 * This means multiply number by unit_from and divide by scale.
	 *
	 * Would like to multiply by unit_from and then divide by scale,
	 * but if the first multiplication would overflow, then need to
	 * divide by scale and then multiply by unit_from.
	 */
	if (number > (UINT64_MAX / (unsigned long long)unit_from)) {
		number = (number / (unsigned long long)scale) *
		    (unsigned long long)unit_from;
	} else {
		number = (number * (unsigned long long)unit_from) /
		    (unsigned long long)scale;
	}

	/*
	 * Now we have number as a count of scale units.
	 * Stop scaling when we reached exa bytes, then something is
	 * probably wrong with our number.
	 */

	while ((number >= scale) && (*uom != 'E')) {
		uom++; /* next unit of measurement */
		save = number;
		number = (number + (scale / 2)) / scale;
	}
	/* check if we should output a decimal place after the point */
	if (save && ((save / scale) < 10)) {
		/* sprintf() will round for us */
		float fnum = (float)save / scale;
		(void) sprintf(buf, "%2.1f%c", fnum, *uom);
	} else {
		(void) sprintf(buf, "%4llu%c", number, *uom);
	}
	return (buf);
}

void
stats_load_counts(xml_node_t *n, stat_delta_t *d)
{
	xml_node_t	*conn	= NULL,
			*lun;
	char		*val;

	bzero(d, sizeof (*d));
	d->device = n->x_value;

	while (conn = xml_node_next(n, XML_ELEMENT_CONN, conn)) {
		lun = NULL;
		while (lun = xml_node_next(conn, XML_ELEMENT_LUN, lun)) {
			if (xml_find_value_str(lun, XML_ELEMENT_READCMDS,
			    &val) == True) {
				d->read_cmds += strtoll(val, NULL, 0);
				free(val);
			}
			if (xml_find_value_str(lun, XML_ELEMENT_WRITECMDS,
			    &val) == True) {
				d->write_cmds += strtoll(val, NULL, 0);
				free(val);
			}
			if (xml_find_value_str(lun, XML_ELEMENT_READBLKS,
			    &val) == True) {
				d->read_blks += strtoll(val, NULL, 0);
				free(val);
			}
			if (xml_find_value_str(lun, XML_ELEMENT_WRITEBLKS,
			    &val) == True) {
				d->write_blks += strtoll(val, NULL, 0);
				free(val);
			}
		}
	}
}

stat_delta_t *
stats_prev_counts(stat_delta_t *cp)
{
	stat_delta_t	*n;

	for (n = stat_head; n; n = n->next) {
		if (strcmp(n->device, cp->device) == 0)
			return (n);
	}
	if ((n = calloc(1, sizeof (*n))) == NULL)
		return (NULL);
	n->device = strdup(cp->device);
	if (stat_head == NULL)
		stat_head = n;
	else {
		n->next = stat_head;
		stat_head = n;
	}
	return (n);
}

void
stats_update_counts(stat_delta_t *p, stat_delta_t *c)
{
	p->read_cmds	+= c->read_cmds - p->read_cmds;
	p->write_cmds	+= c->write_cmds - p->write_cmds;
	p->read_blks	+= c->read_blks - p->read_blks;
	p->write_blks	+= c->write_blks - p->write_blks;
}

void
stats_free()
{
	stat_delta_t	*n;

	/* CSTYLED */
	for (;stat_head;) {
		n = stat_head->next;
		free(stat_head->device);
		free(stat_head);
		stat_head = n;
	}
}

static char spaces[128];

/*
 * []----
 * | dospace -- generate a string which has the appropriate number of spaces
 * |
 * | NOTE: Since this function modifies a static buffer usage of this
 * | function may not be what's expected. For example:
 * | printf("%sfoo%sbar\n", dospace(1), dospace(2)); would produce
 * | '    foo    bar'
 * | instead of
 * | '    foo        bar'
 * []----
 */
char *
dospace(int n)
{
	(void) memset(spaces, ' ', sizeof (spaces));
	spaces[sizeof (spaces) - 1] = '\0';

	if (n < sizeof (spaces))
		spaces[n * 4] = '\0';
	return (spaces);
}
