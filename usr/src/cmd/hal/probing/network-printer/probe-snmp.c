/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>

#undef PACKAGE_STRING
#undef PACKAGE_VERSION

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "logger.h"
#include "printer.h"

static int
hrDeviceDesc_to_info(char *string, char **manufacturer, char **model,
		char **description)
{
	int rc = -1;
	char *s;

	if (string == NULL)
		return (-1);

	/* if it has : and ; in it, it's probably a 1284 device id */
	if ((strchr(string, ':') != NULL) && (strchr(string, ';') != NULL)) {
		rc = ieee1284_devid_to_printer_info(string, manufacturer, model,
				description, NULL, NULL, NULL);
	} else {
		rc = 0;
		*description = strdup(string);
		*manufacturer = strdup(string);
		if ((s = strchr(*manufacturer, ' ')) != NULL) {
			*s++ = '\0';
			*model = strdup(s);
		}
	}

	return (rc);
}

static struct snmp_pdu *
snmp_get_item(char *host, char *community, char *mib_item)
{
	struct snmp_session session, *ss;
	struct snmp_pdu *request = NULL, *result = NULL;
	oid Oid[MAX_OID_LEN];
	unsigned int oid_len = MAX_OID_LEN;

	/* initialize the SNMP session */
	snmp_sess_init(&session);
	session.peername = host;
	session.community = (uchar_t *)community;
	session.community_len = strlen((const char *)session.community);
	session.version = SNMP_VERSION_1;
	session.retries = 0;

	if ((ss = snmp_open(&session)) == NULL)
		return (NULL);

	/* add the requested data */
	if (!read_objid(mib_item, Oid, &oid_len))
		snmp_perror(mib_item);

	/* initialize the request PDU */
	request = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(request, Oid, oid_len);

	(void) snmp_synch_response(ss, request, &result);

	snmp_close(ss);

	return (result);
}

static char *
snmp_get_string(char *host, char *community, char *mib_item)
{
	char *result = NULL;
	struct snmp_pdu *response = NULL;

	response = snmp_get_item(host, community, mib_item);

	if ((response != NULL) && (response->errstat == SNMP_ERR_NOERROR)) {
		struct variable_list *v = response->variables;

		if (v->type == ASN_OCTET_STR) {
			result = calloc(1, v->val_len + 1);
			memcpy(result, v->val.string, v->val_len);
		}
	}

	HAL_DEBUG(("snmp_get_string(%s, %s, %s): %s", host, community, mib_item,
		(result?result:"NULL")));

	if (response != NULL)
		snmp_free_pdu(response);

	return (result);
}

static int
snmp_brother_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * Brother printers appear to store
	 *	1284 DevID	SNMPv2-SMI::enterprises.2435.2.3.9.1.1.7.0
	 *	Serial Number	SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.1.0
	 */
	tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.2435.2.3.9.1.1.7.0");
	if (tmp != NULL) {
		rc = ieee1284_devid_to_printer_info(tmp, manufacturer, model,
				description, NULL, serial_no, command_set);
		free(tmp);

		if (*serial_no == NULL)
			*serial_no = snmp_get_string(hostname, community,
				"SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.1.0");
	}

	return (rc);
}

static int
snmp_ricoh_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * OKI printers appear to store
	 *	1284 DevID	SNMPv2-SMI::enterprises.367.3.2.1.1.1.11.0
	 *	Serial Number	SNMPv2-SMI::enterprises.367.3.2.1.2.1.4.0
	 */
	tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.367.3.2.1.1.1.11.0");
	if (tmp != NULL) {
		rc = ieee1284_devid_to_printer_info(tmp, manufacturer, model,
				description, NULL, serial_no, command_set);
		free(tmp);

		if (*serial_no == NULL)
			*serial_no = snmp_get_string(hostname, community,
				"SNMPv2-SMI::enterprises.367.3.2.1.2.1.4.0");
	}

	return (rc);
}

static int
snmp_lexmark_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * Lexmark printers appear to store
	 *	1284 DevID	SNMPv2-SMI::enterprises.641.2.1.2.1.3.1
	 *	Serial Number	SNMPv2-SMI::enterprises.641.2.1.2.1.6.1
	 */
	tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.641.2.1.2.1.3.1");
	if (tmp != NULL) {
		rc = ieee1284_devid_to_printer_info(tmp, manufacturer, model,
				description, NULL, serial_no, command_set);
		free(tmp);

		if (*serial_no == NULL)
			*serial_no = snmp_get_string(hostname, community,
				"SNMPv2-SMI::enterprises.641.2.1.2.1.6.1");
	}

	return (rc);
}

static int
snmp_xerox_phaser_printer_info(char *hostname, char *community,
		char **manufacturer, char **model, char **description,
		char **serial_no, char ***command_set, char **uri)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * Xerox Phaser XXXX printers store their
	 *	1284 DevID	SNMPv2-SMI::enterprises.253.8.51.1.2.1.20.1
	 *	Manufacturer:
	 *			SNMPv2-SMI::enterprises.128.2.1.3.1.1.0
	 *			SNMPv2-SMI::enterprises.23.2.32.3.2.1.10.1.16
	 *			SNMPv2-SMI::enterprises.23.2.32.4.1.0
	 *	Model:
	 *			SNMPv2-SMI::enterprises.128.2.1.3.1.2.0
	 *			SNMPv2-SMI::enterprises.23.2.32.3.2.1.10.1.17
	 *			SNMPv2-SMI::enterprises.23.2.32.4.2.0
	 *	Description	SNMPv2-SMI::enterprises.253.8.53.3.2.1.2.1
	 *	Serial Number	SNMPv2-SMI::enterprises.253.8.53.3.2.1.3.1
	 *	Uri		SNMPv2-SMI::enterprises.128.2.1.3.6.23.1.5.1
	 */

	tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.253.8.51.1.2.1.20.1");
	if (tmp != NULL) {
		rc = ieee1284_devid_to_printer_info(tmp, manufacturer, model,
				description, NULL, serial_no, command_set);
		free(tmp);
	}

	if (*manufacturer == NULL)
		*manufacturer = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.128.2.1.3.1.1.0");
	if (*manufacturer == NULL)
		*manufacturer = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.23.2.32.3.2.1.10.1.16");
	if (*manufacturer == NULL)
		*manufacturer = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.23.2.32.4.1.0");

	if (*model == NULL)
		*model = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.128.2.1.3.1.2.0");
	if (*model == NULL)
		*model = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.23.2.32.3.2.1.10.1.17");
	if (*model == NULL)
		*model = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.23.2.32.4.2.0");

	if (*serial_no == NULL)
		*serial_no = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.253.8.53.3.2.1.3.1");

	if ((*manufacturer != NULL) && (*model != NULL))
		rc = 0;

	return (rc);
}

static int
snmp_qms_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set, char **uri)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * MINOLTA-QMS printers appear to store
	 *	Prouct Name	SNMPv2-SMI::enterprises.2590.1.1.2.1.5.7.14.2.1.1.16.1
	 *	Serial Number	SNMPv2-SMI::enterprises.2590.1.1.1.5.5.1.1.3.2
	 *	URI		SNMPv2-SMI::enterprises.2590.1.1.2.1.5.7.14.2.2.1.3.1.1
	 *			SNMPv2-SMI::enterprises.2590.1.1.2.1.5.7.14.2.2.1.3.1.2
	 */
	tmp = snmp_get_string(hostname, community,
		"SNMPv2-SMI::enterprises.2590.1.1.2.1.5.7.14.2.1.1.16.1");
	if (tmp != NULL) {
		rc = hrDeviceDesc_to_info(tmp, manufacturer, model,
					description);
		free(tmp);

		if (*serial_no == NULL)
			*serial_no = snmp_get_string(hostname, community,
				"SNMPv2-SMI::enterprises.2590.1.1.1.5.5.1.1.3.2");
		tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.2590.1.1.2.1.5.7.14.2.2.1.3.1.2");
		if (tmp == NULL)
			tmp = snmp_get_string(hostname, community,
				"SNMPv2-SMI::enterprises.2590.1.1.2.1.5.7.14.2.2.1.3.1.1");
		if (tmp != NULL)
			*uri = tmp;
	}

	return (rc);
}

static int
snmp_oki_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * OKI printers appear to store
	 *	Prouct Name	SNMPv2-SMI::enterprises.2001.1.2.683.1.3
	 *	Serial Number	SNMPv2-SMI::enterprises.2001.1.2.683.1.5
	 */
	tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.2001.1.2.683.1.3");
	if (tmp != NULL) {
		rc = ieee1284_devid_to_printer_info(tmp, manufacturer, model,
				description, NULL, serial_no, command_set);
		free(tmp);

		if (*serial_no == NULL)
			*serial_no = snmp_get_string(hostname, community,
				"SNMPv2-SMI::enterprises.2001.1.2.683.1.5");
	}

	return (rc);
}

static int
snmp_hp_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * HP printers appear to store
	 *	1284 DevID	SNMPv2-SMI::enterprises.11.2.3.9.1.1.7.0
	 *	Serial Number	SNMPv2-SMI::enterprises.2.3.9.4.2.2.5.1.1.17
	 */
	tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.11.2.3.9.1.1.7.0");
	if (tmp != NULL) {
		rc = ieee1284_devid_to_printer_info(tmp, manufacturer, model,
				description, NULL, serial_no, command_set);
		free(tmp);

		if (*serial_no == NULL)
			*serial_no = snmp_get_string(hostname, community,
				"SNMPv2-SMI::enterprises.2.3.9.4.2.2.5.1.1.17");
	}

	return (rc);
}

static int
snmp_ppm_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * The PWG portMon MIB stores
	 *	1284 DevID	SNMPv2-SMI::enterprises.2699.1.2.1.1.1.3`
	 */
	tmp = snmp_get_string(hostname, community,
			"SNMPv2-SMI::enterprises.2699.1.2.1.1.1.3");
	if (tmp != NULL) {
		rc = ieee1284_devid_to_printer_info(tmp, manufacturer, model,
				description, NULL, serial_no, command_set);
		free(tmp);
	}

	return (rc);
}

static int
snmp_prt_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	/*
	 * The Printer Printer MIB stores
	 *	Vendor	 SNMPv2-SMI::mib-2.43.8.2.1.14.1.1
	 *	Model	 SNMPv2-SMI::mib-2.43.8.2.1.15.1.1
	 *	Serial	 SNMPv2-SMI::mib-2.43.8.2.1.17.1.1
	 */

	if (*manufacturer == NULL)
		*manufacturer = snmp_get_string(hostname, community,
				"SNMPv2-SMI::mib-2.43.8.2.1.14.1.1");
	if (*model == NULL)
		*model = snmp_get_string(hostname, community,
				"SNMPv2-SMI::mib-2.43.8.2.1.15.1.1");
	if (*serial_no == NULL)
		*serial_no = snmp_get_string(hostname, community,
				"SNMPv2-SMI::mib-2.43.8.2.1.17.1.1");

	if (*manufacturer != NULL)
		rc = 0;

	return (rc);
}

static int
snmp_host_resource_printer_info(char *hostname, char *community,
		char **manufacturer, char **model, char **description,
		char **serial_no, char ***command_set)
{
	int rc = -1;
	char *tmp = NULL;

	tmp = snmp_get_string(hostname, community,
			"HOST-RESOURCES-MIB::hrDeviceDescr.1");
	if (tmp != NULL) {
		rc = hrDeviceDesc_to_info(tmp, manufacturer, model,
					description);
		free(tmp);
	}

	return (rc);
}

int
snmp_printer_info(char *hostname, char *community, char **manufacturer,
		char **model, char **description, char **serial_no,
		char ***command_set, char **uri)
{
	char *tmp = NULL;

	init_snmp("network-printer-probe");
	init_mib();

	if (snmp_brother_printer_info(hostname, community, manufacturer, model,
			description, serial_no, command_set) == 0) {
		return (0);
	} else if (snmp_ricoh_printer_info(hostname, community, manufacturer,
			model, description, serial_no, command_set) == 0) {
		return (0);
	} else if (snmp_lexmark_printer_info(hostname, community, manufacturer,
			model, description, serial_no, command_set) == 0) {
		return (0);
	} else if (snmp_xerox_phaser_printer_info(hostname, community,
			manufacturer, model, description, serial_no,
			command_set, uri) == 0) {
		return (0);
	} else if (snmp_qms_printer_info(hostname, community, manufacturer,
			model, description, serial_no, command_set, uri) == 0) {
		return (0);
	} else if (snmp_oki_printer_info(hostname, community, manufacturer,
			model, description, serial_no, command_set) == 0) {
		return (0);
	} else if (snmp_hp_printer_info(hostname, community, manufacturer,
			model, description, serial_no, command_set) == 0) {
		return (0);
	} else if (snmp_ppm_printer_info(hostname, community, manufacturer,
			model, description, serial_no, command_set) == 0) {
		return (0);
	} else if (snmp_prt_printer_info(hostname, community, manufacturer,
			model, description, serial_no, command_set) == 0) {
		return (0);
	} else if (snmp_host_resource_printer_info(hostname, community,
			manufacturer, model, description, serial_no,
			command_set) == 0) {
		return (0);
	}

	return (-1);
}

#ifdef NOTDEF

#define	NP(x)	(x?x:"")

int
main(int ac, char *av[])
{
	int i;

	for (i = 1; av[i] != NULL; i++) {
		char *hostname = av[i], *manufacturer = NULL, *model = NULL,
		     *description = NULL, *serial_no = NULL,
		     **command_set = NULL, *uri = NULL;
		int rc;

		rc = snmp_printer_info(hostname, &manufacturer, &model,
				&description, &serial_no, &command_set, &uri);
		printf("SNMP data for %s...(%d)\n", hostname, rc);
		printf("\tvendor = %s\n", NP(manufacturer));
		printf("\tproduct = %s\n", NP(model));
		printf("\tdescription = %s\n", NP(description));
		printf("\tserial = %s\n", NP(serial_no));
		printf("\tdevice = %s\n", NP(uri));

		if (command_set != NULL) {
			int j;

			printf("\tcommand set = \n");
			for (j = 0; command_set[j] != NULL; j++)
				printf("\t\t%s\n", command_set[j]);
		}
	}

	return (0);
}
#endif
