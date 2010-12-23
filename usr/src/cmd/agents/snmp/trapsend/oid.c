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
 *
 * Copyright 1996 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <nlist.h>

#include "snmp_msg.h"
#include "impl.h"
#include "trace.h"
#include "snmp.h"
#include "pdu.h"
#include "trap.h"
#include "error.h"

#define BUFSIZE 256


/* get_oid_from_file
   it finds the first oid which enterprise string match the input.
   */

static Oid *get_oid_with_name(char *inbuf, char *enterprise_str)
{
	char *str;
	char *name_ptr;
	Oid  *oid = NULL; 

	if ((inbuf== NULL) || (inbuf[0]== '#')) return (NULL);
	
	/* first "  for name */
	if ((str = strchr(inbuf, '"')) == NULL) return (NULL);
	*str++;
	name_ptr = str; 

		/* second " for name */
	if ((str = strchr(str, '"')) == NULL) return (NULL);  
	*str = '\0'; 

	if (!strncasecmp(name_ptr, enterprise_str, strlen(enterprise_str))) {
		*str++;
		/* first " for oid_str*/
		if ((str = strchr(str, '"')) == NULL)  return (NULL);  
		*str++;
		name_ptr = str;

		/* second " for oid_str*/
		if ((str = strchr(str, '"')) == NULL) return (NULL);  
		*str = '\0';
		oid = SSAOidStrToOid(name_ptr,error_label);
	}

	return(oid);
	
}

Oid *get_oid(char *enterprise_str)
{
	char *snm_home;
	Oid *oid = NULL;
	FILE *fd;
	char inbuf[BUFSIZE];
	
	if ((snm_home = getenv("SNMHOME")) == NULL ) {
		sprintf(inbuf,
				"/etc/snmp/conf/enterprises.oid");
	}
	else {
		sprintf(inbuf,
				"%s/agents/enterprise.oid", snm_home);
	}

    fd = fopen(inbuf, "r");
    if (fd == NULL) {
		fprintf(stderr, "Cannot open %s\n", inbuf);
		return (NULL);
    }
	else {
		if(trace_level > 0)	{
			trace("Parsing %s\n", inbuf);
		}
    }

	while (fgets(inbuf, BUFSIZE, fd)) {
		oid = get_oid_with_name(inbuf, enterprise_str);
		if (oid != NULL) {
			fclose (fd);
			return(oid);
		}
	}
    fclose(fd);

	return (oid); 
}


/* error return NULL,  success variable */
SNMP_variable *get_variable(char *buf)
{
	char name[BUFSIZE];
	char type_str[BUFSIZE];
	u_char type; 
	char value[BUFSIZE];
	SNMP_value snmp_value; 
	SNMP_variable *variable = NULL;
	Oid *name_oid, *value_oid;
	int count; 
	
	char *s;
    int i;
	
    /* get the attribute name and the type */
    if (sscanf(buf, "%s %s", name, type_str) != 2)
      return(NULL);

    /* get the value */
    /* everything after the '(' is the value field */
    if (!(s = (char *)strchr(buf, '(')))
		return(NULL);
    s++;
	count = 1; 
    
    for (; *s && *s == ' '; s++); /* skip leading blanks */
    for (i = 0; *s && count && i< BUFSIZE ; s++, i++) {
		if (*s == ')')
			count --;
		if (*s == '(')
			count ++;
		if (count)
			value[i] = *s;
		else
			value[i] = '\0';
	}
	
	if (i>= BUFSIZE) {
		fprintf(stderr, "object value is too long!\n");
		usage(); 
	}
    value[i] = '\0';

    if (strcmp(type_str, "STRING") == 0) {
		type = STRING;
		snmp_value.v_string.chars = (u_char *) value;
		snmp_value.v_string.len = strlen(value);
	}
    else if (strcmp(type_str, "IPADDRESS") == 0) {
		type = IPADDRESS;
		snmp_value.v_string.chars = (u_char *) value;
		snmp_value.v_string.len = strlen(value);
	}
    else if (strcmp(type_str, "OPAQUE") == 0) {
		type = OPAQUE;
		snmp_value.v_string.chars = (u_char *) value;
		snmp_value.v_string.len = strlen(value);
	}
    else if (strcmp(type_str, "INTEGER") == 0) {
		type = INTEGER;
		snmp_value.v_integer = atoi(value);
	}
    else if (strcmp(type_str, "COUNTER") == 0) {
		type = COUNTER;
		snmp_value.v_integer = atoi(value);
	}
    else if (strcmp(type_str, "GAUGE") == 0) {
		type = GAUGE;
		snmp_value.v_integer = atoi(value);
	}
    else if (strcmp(type_str, "TIMETICKS") == 0) {
		type = TIMETICKS;
		snmp_value.v_integer = atoi(value);
	}
    else if (strcmp(type_str, "OBJECTID") == 0) {
		type = OBJID;
		if ((value_oid = SSAOidStrToOid(value,error_label)) == NULL) return (NULL) ;
		snmp_value.v_oid.subids = value_oid->subids;
		snmp_value.v_oid.len = value_oid->len; 
	}
	else return (NULL);


	if ((name_oid = SSAOidStrToOid(name,error_label)) == NULL) return (NULL); 
		
	variable = snmp_typed_variable_new(name_oid, 
									   type, &snmp_value, error_label);
	SSAOidFree(name_oid);
    return(variable);
}  /* get_variable */


