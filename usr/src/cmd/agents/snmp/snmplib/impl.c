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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "snmp_msg.h"
#include "impl.h"
#include "asn1.h"
#include "snmp.h"
#include "error.h"
 

/********************************************************************/

char *pdu_type_string(u_char type)
{
	static char buffer[50];


	switch(type)
	{
		case GET_REQ_MSG:
			sprintf(buffer, "GET_REQ_MSG (0x%x)", type);
			break;
		case GETNEXT_REQ_MSG:
			sprintf(buffer, "GETNEXT_REQ_MSG (0x%x)", type);
			break;
		case GET_RSP_MSG:
			sprintf(buffer, "GET_RSP_MSG (0x%x)", type);
			break;
		case SET_REQ_MSG:
			sprintf(buffer, "SET_REQ_MSG (0x%x)", type);
			break;
		case TRP_REQ_MSG:
			sprintf(buffer, "TRP_MSG (0x%x)", type);
			break;
		default:
			sprintf(buffer, "UNKNOWN! (0x%x)", type);
			break;
	}

	return buffer;
}


/********************************************************************/

char *asn1_type_string(u_char type)
{
	static char buffer[50];


	switch(type)
	{
		case ASN_INTEGER:
			sprintf(buffer, "INTEGER (0x%x)", type);
			break;
		case COUNTER:
			sprintf(buffer, "COUNTER (0x%x)", type);
			break;
		case GAUGE:
			sprintf(buffer, "GAUGE (0x%x)", type);
			break;
		case TIMETICKS:
			sprintf(buffer, "TIMETICKS (0x%x)", type);
			break;
		case ASN_OCTET_STR:
			sprintf(buffer, "OCTET STRING (0x%x)", type);
			break;
		case IPADDRESS:
			sprintf(buffer, "IP ADDRESS (0x%x)", type);
			break;
		case OPAQUE:
			sprintf(buffer, "OPAQUE (0x%x)", type);
			break;
		case ASN_OBJECT_ID:
			sprintf(buffer, "OBJECT IDENTIFIER (0x%x)", type);
			break;
		case ASN_NULL:
			sprintf(buffer, "NULL (0x%x)", type);
			break;
		default:
			sprintf(buffer, "UNKNOWN! (0x%x)", type);
			break;
	}

	return buffer;
}


/********************************************************************/

char *error_status_string(int status)
{
	static char buffer[50];


	switch(status)
	{
		case SNMP_ERR_NOERROR:
			sprintf(buffer, "noError(%d)", status);
			break;
		case SNMP_ERR_TOOBIG:
			sprintf(buffer, "tooBig(%d)", status);
			break;
		case SNMP_ERR_NOSUCHNAME:
			sprintf(buffer, "noSuchName(%d)", status);
			break;
		case SNMP_ERR_BADVALUE:
			sprintf(buffer, "badValue(%d)", status);
			break;
		case SNMP_ERR_READONLY:
			sprintf(buffer, "readOnly(%d)", status);
			break;
		case SNMP_ERR_GENERR:
			sprintf(buffer, "genErr(%d)", status);
			break;
		default:
			sprintf(buffer, "UNKNOWN! (%d)", status);
			break;
	}

	return buffer;
}


/********************************************************************/

char *generic_trap_string(int generic)
{
	static char buffer[50];


	switch(generic)
	{
		case SNMP_TRAP_COLDSTART:
			sprintf(buffer, "coldStart(%d)", generic);
			break;
		case SNMP_TRAP_WARMSTART:
			sprintf(buffer, "warmStart(%d)", generic);
			break;
		case SNMP_TRAP_LINKDOWN:
			sprintf(buffer, "linkDown(%d)", generic);
			break;
		case SNMP_TRAP_LINKUP:
			sprintf(buffer, "linkUp(%d)", generic);
			break;
		case SNMP_TRAP_AUTHFAIL:
			sprintf(buffer, "authentificationFailure(%d)", generic);
			break;
		case SNMP_TRAP_EGPNEIGHBORLOSS:
			sprintf(buffer, "egpNeighborLoss(%d)", generic);
			break;
		case SNMP_TRAP_ENTERPRISESPECIFIC:
			sprintf(buffer, "enterpriseSpecific(%d)", generic);
			break;
		default:
			sprintf(buffer, "UNKNOWN! (%d)", generic);
			break;
	}

	return buffer;
}


/********************************************************************/

/* we should check if the buffer is not too small */

char *SSAOidString(Oid *oid)
{
	static char buffer[1000];
	int i;
	int32_t len;


	if(oid == NULL)
	{
		sprintf(buffer, "oid is NULL!");
		return buffer;
	}

	sprintf(buffer, "");

	if(oid->len == 0)
	{
		return buffer;
	}

	for(i = 0; i < oid->len - 1; i++) {
		/* LINTED */
		len = (int32_t)strlen(buffer);
		sprintf(&(buffer[len]), "%lu.", oid->subids[i]);
	}
	/* LINTED */
	len = (int32_t)strlen(buffer);
	sprintf(&(buffer[len]), "%lu", oid->subids[oid->len - 1]);

	return buffer;
}


/********************************************************************/

char *timeval_string(struct timeval *tv)
{
	static char buffer[50];


	if(tv == NULL)
	{
		sprintf(buffer, "tv is NULL!");
		return buffer;
	}

	sprintf(buffer, "%ld sec %ld usec", tv->tv_sec, tv->tv_usec);
	return buffer;
}


/********************************************************************/

char *ip_address_string(IPAddress *ip_address)
{
	static char buffer[50];
	struct hostent *hp;


	if(ip_address == NULL)
	{
		sprintf(buffer, "BUG: ip_address_string(): ip_address is NULL");
		return buffer;
	}

	hp = gethostbyaddr((char *) &(ip_address->s_addr), 4, AF_INET);
	if(hp)
	{
		sprintf(buffer, "%s", hp->h_name);
	}
	else
	{
		sprintf(buffer, "%s", inet_ntoa(*ip_address));
	}

	return buffer;
}


/********************************************************************/

char *address_string(Address *address)
{
	static char buffer[50];
	struct hostent *hp;


	if(address == NULL)
	{
		sprintf(buffer, "BUG: address_string(): address is NULL");
		return buffer;
	}

	hp = gethostbyaddr((char *) &(address->sin_addr.s_addr), 4, AF_INET);
	if(hp)
	{
		sprintf(buffer, "%s.%d", hp->h_name, address->sin_port);
	}
	else
	{
		sprintf(buffer, "%s.%d", inet_ntoa(address->sin_addr), address->sin_port);
	}

	return buffer;
}


/********************************************************************/

int SSAStringCpy(String *string1, String *string2, char *error_label)
{
	error_label[0] = '\0';

	if(string1 == NULL)
	{
		sprintf(error_label, "BUG: SSAStringCpy(): string1 is NULL");
		return -1;
	}

	if(string2 == NULL)
	{
		sprintf(error_label, "BUG: SSAStringCpy(): string2 is NULL");
		return -1;
	}

	if(string1->chars)
	{
		sprintf(error_label, "BUG: SSAStringCpy(): string1->chars is not NULL");
		return -1;
	}

	if(string1->len)
	{
		sprintf(error_label, "BUG: SSAStringCpy(): string1->len is not 0");
		return -1;
	}

	if(string2->len == 0)
	{
		return 0;
	}

	string1->chars = (u_char *) malloc(string2->len);
	if(string1->chars == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return -1;
	}

	memcpy(string1->chars, string2->chars, string2->len);
	string1->len = string2->len;


	return 0;
}


/********************************************************************/

void SSAStringZero(String *string)
{
	if(string == NULL)
	{
		(void)fprintf(stderr, "BUG: SSAStringZero(): string is NULL");
		return;
	}

	if(string->chars)
	{
		free(string->chars);
		string->chars = NULL;
	}
	string->len = 0;


	return;
}


/********************************************************************/

int SSAStringInit(String *string, u_char *chars, int len, char *error_label)
{
	error_label[0] = '\0';

	if(string == NULL)
	{
		sprintf(error_label, "BUG: SSAStringInit(): string is NULL");
		return -1;
	}

	if(string->chars != NULL)
	{
		sprintf(error_label, "BUG: SSAStringInit(): string->chars is not NULL");
		return -1;
	}

	if(string->len != 0)
	{
		sprintf(error_label, "BUG: SSAStringInit(): string->len is not 0");
		return -1;
	}

	if(len != 0)
	{
		string->chars = (u_char *) malloc(len);
		if(string->chars == NULL)
		{
			sprintf(error_label, ERR_MSG_ALLOC);
			return -1;
		}
		memcpy(string->chars, chars, len);
		string->len = len;
	}


	return 0;
}


/********************************************************************/

/*
 *	SSAOidCmp() returns:
 *
 *		0 if oid1 == oid2
 *		1 if oid1 > oid2
 *		-1 if oid1 < oid2
 */

int SSAOidCmp(Oid *oid1, Oid *oid2)
{
	int min;
	int i;


	if(oid1 == NULL)
	{
		(void)fprintf(stderr, "BUG: SSAOidCmp(): oid1 is NULL");
		return -2;
	}

	if(oid2 == NULL)
	{
		(void)fprintf(stderr, "BUG: SSAOidCmp(): oid2 is NULL");
		return -2;
	}

	min = MIN(oid1->len, oid2->len);

	for(i = 0; i < min; i++)
	{
		if(oid1->subids[i] > oid2->subids[i])
		{
			return 1;
		}

		if(oid1->subids[i] < oid2->subids[i])
		{
			return -1;
		}
	}

	if(oid1->len == oid2->len)
	{
		return 0;
	}
	else
	if(oid1->len > oid2->len)
	{
		return 1;
	}
	else
	{
		return -1;
	}
}


/********************************************************************/

int SSAOidCpy(Oid *oid1, Oid *oid2, char *error_label)
{
	error_label[0] = '\0';

	if(oid1 == NULL) {
		(void)sprintf(error_label, "BUG: SSAOidCpy(): oid1 is NULL");
		return -1;
	}

	if(oid2 == NULL) {
		(void)sprintf(error_label, "BUG: SSAOidCpy(): oid2 is NULL");
		return -1;
	}

	if(oid2->len == 0) {
		return 0;
	}

	if(oid1->subids) {
		(void)sprintf(error_label, "BUG: SSAOidCpy(): oid1->subids is not NULL");
		return -1;
	}

	if(oid1->len) {
		(void)sprintf(error_label, "BUG: SSAOidCpy(): oid1->len is not 0");
		return -1;
	}


	oid1->subids = (Subid *) malloc(oid2->len * (int32_t)sizeof(Subid));
	if(oid1->subids == NULL) {
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		return -1;
	}

	(void)memcpy(oid1->subids, oid2->subids, oid2->len * (int32_t)sizeof(Subid));
	oid1->len = oid2->len;

	return 0;
}


/********************************************************************/

Oid *SSAOidDup(Oid *oid, char *error_label)
{
	Oid *new = NULL;


	error_label[0] = '\0';

	if(oid == NULL)
	{
		sprintf(error_label, "BUG: SSAOidDup(): oid is NULL");
		return NULL;
	}

	new = (Oid *) malloc(sizeof(Oid));
	if(new == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(new, 0, sizeof(Oid));

	if(SSAOidCpy(new, oid, error_label))
	{
		free(new);
		return NULL;
	}

	return new;
}


/********************************************************************/

Oid *SSAOidNew()
{
 	Oid *oid = NULL;
 	oid = (Oid *) malloc(sizeof(Oid));
 	oid->subids = NULL;
 	oid->len = 0;
 	return (oid); 
}

/********************************************************************/

void SSAOidZero(Oid *oid)
{
	if(oid == NULL)
	{
		(void)fprintf(stderr, "BUG: SSAOidZero(): oid is NULL");
		return;
	}

	if(oid->subids)
	{
		free(oid->subids);
		oid->subids = NULL;
	}
	oid->len = 0;
}


/********************************************************************/

void SSAOidFree(Oid *oid)
{
	if(oid == NULL) {
		return;
	}

	SSAOidZero(oid);
	free(oid);
}


/********************************************************************/

int SSAOidInit(Oid *oid, Subid *subids, int len, char *error_label)
{
	error_label[0] = '\0';

	if(oid == NULL)
	{
		sprintf(error_label, "BUG: SSAOidInit(): oid is NULL");
		return -1;
	}

	if(oid->subids != NULL)
	{
		sprintf(error_label, "BUG: SSAOidInit(): oid->subids is not NULL");
		return -1;
	}

	if(oid->len != 0)
	{
		sprintf(error_label, "BUG: SSAOidInit(): oid->len is not 0");
		return -1;
	}

	if(len != 0)
	{
		oid->subids = (Subid *) malloc(len * (int32_t)sizeof(Subid));
		if(oid->subids == NULL)
		{
			sprintf(error_label, ERR_MSG_ALLOC);
			return -1;
		}
		(void)memcpy(oid->subids, subids, len * (int32_t)sizeof(Subid));
		oid->len = len;
	}


	return 0;
}


/********************************************************************/

int get_my_ip_address(IPAddress *my_ip_address, char *error_label)
{
	struct utsname name;
	struct hostent *hp;


	error_label[0] = '\0';

	if(uname(&name) == -1)
	{
		sprintf(error_label, ERR_MSG_UNAME,
			errno_string());
		return -1;
	}

	if((hp = gethostbyname(name.nodename)) == NULL)
	{
		sprintf(error_label, ERR_MSG_GETHOSTBYNAME,
			name.nodename, h_errno_string());
		return -1;
	}

	if(hp->h_length != 4)
	{
		sprintf(error_label, ERR_MSG_HOSTENT_BAD_IP_LENGTH,
			hp->h_length);
		return -1;
	}

	if(*hp->h_addr_list == NULL)
	{
		sprintf(error_label, ERR_MSG_HOSTENT_MISSING_IP_ADDRESS);
		return -1;
	}

	memcpy(&my_ip_address->s_addr, *hp->h_addr_list, 4);


	return 0;
}


/********************************************************************/

int name_to_ip_address(char *name, IPAddress *ip_address, char *error_label)
{
	error_label[0] = '\0';


	if(name == NULL)
	{
		sprintf(error_label, "BUG: name_to_ip_address(): name is NULL");
		return -1;
	}

	if(ip_address == NULL)
	{
		sprintf(error_label, "BUG: name_to_ip_address(): ip_address is NULL");
		return -1;
	}

	/* try to find the IP address from the name */
	if(isdigit(name[0]))
	{
		if((int) (ip_address->s_addr = inet_addr(name)) == -1)
		{
			sprintf(error_label, ERR_MSG_BAD_IP_ADDRESS, name);
			return -1;
		}
	}
	else
	{
		struct hostent *hp;


		hp = gethostbyname(name);
		if(hp == NULL)
		{
			sprintf(error_label, ERR_MSG_BAD_HOSTNAME, name);
			return -1;
		}

		if(hp->h_length != 4)
		{
			sprintf(error_label, ERR_MSG_HOSTENT_BAD_IP_LENGTH,
				hp->h_length);
			return -1;
		}

		if(*hp->h_addr_list == NULL)
		{
			sprintf(error_label, ERR_MSG_HOSTENT_MISSING_IP_ADDRESS);
			return -1;
		}

		memcpy(&(ip_address->s_addr), *hp->h_addr_list, 4);
	}


	return 0;
}

char *SSAStringToChar(String str)
{
  static char buffer[100];

  buffer[0] = '\0';
  memcpy(buffer,str.chars,str.len);
  return buffer;
}

/* error return NULL, success return Oid ptr */
Oid *SSAOidStrToOid (char *name, char *error_label)
{
        Oid *name_oid;
        Subid *subids;
        int len = 0;
        int i;
        char *num_c;
         
        for (i=0; name[i] != '\0'; i++) {
      if (name[i] == '.')
          len++;
          else if (!isdigit(name[i])) {
                  (void)fprintf(stderr, "%s is not a valid oid name\n",  name);
                  return(NULL);
          }
        }

        if (!len ) {
                (void)fprintf(stderr,"%s is not a valid oid name\n",  name);
                return (NULL); /* not a valid name */
        }

        len++;
        subids = (Subid *) malloc(len * (int32_t)sizeof(Subid));
        if (subids == NULL) {
                (void)fprintf(stderr,"cannot malloc\n");
                return (NULL) ;
        }
        if ((num_c = strtok(name, "."))== NULL) {
                free(subids);
                return (NULL);
        }
        i = 0;
	/* LINTED */
        subids[i] = (Subid) atol(num_c);
        i++;
        while (( num_c = strtok(NULL, ".")) != NULL ) {
		/* LINTED */
                subids[i] = (Subid) atol(num_c);
                i++;
        }

        name_oid = SSAOidNew();
        (void)SSAOidInit(name_oid, subids, len, error_label);
        free(subids);
        return(name_oid);
}

