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

#ifndef _ISNSADM_H
#define	_ISNSADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <cmdparse.h>

#ifdef _BIG_ENDIAN
#define	htonll(x)   (x)
#define	ntohll(x)   (x)
#else
#define	htonll(x)   ((((unsigned long long)htonl(x)) << 32) + htonl(x >> 32))
#define	ntohll(x)   ((((unsigned long long)ntohl(x)) << 32) + ntohl(x >> 32))
#endif

/* DEFINES */
/* subcommands */
#define	LISTNODE		SUBCOMMAND(0)
#define	LISTDD			SUBCOMMAND(1)
#define	LISTDDSET		SUBCOMMAND(2)
#define	CREATEDD		SUBCOMMAND(3)
#define	CREATEDDSET		SUBCOMMAND(4)
#define	DELETEDD		SUBCOMMAND(5)
#define	DELETEDDSET		SUBCOMMAND(6)
#define	ADDNODE			SUBCOMMAND(7)
#define	ADDDD			SUBCOMMAND(8)
#define	REMOVENODE		SUBCOMMAND(9)
#define	REMOVEDD		SUBCOMMAND(10)
#define	MODIFYDD		SUBCOMMAND(11)
#define	MODIFYDDSET		SUBCOMMAND(12)
#define	ENABLEDDSET		SUBCOMMAND(13)
#define	DISABLEDDSET		SUBCOMMAND(14)
#define	SHOWCONFIG		SUBCOMMAND(15)

/* reader lookup return value definition */
#define	NO_MATCH		0
#define	READER_MATCH		1
#define	END_READER_MATCH	2

/* Association Request type */
typedef enum {
	dd_to_node,
	node_to_dd,
	dd_to_ddset,
	ddset_to_dd
} association_t;

/* Modify Requet type */
typedef enum {
	dd_name_change,
	ddset_name_change,
	dds_state_change,
	dd_bootlist_feature_change
} modify_type;

#define	COMMAND_SYNTAX_FAILED	1

/*  msg code */
typedef enum {
    SUBCOMMAND_SUCCESS = 200,
    SUCCESS_WITH_NO_OBJECT,
    ERROR_PARTIAL_SUCCESS,
    ERROR_PARTIAL_FAILURE,
    ERROR_NO_ADDITIONAL_PARTIAL_FAILIRE_INFO,
    ERROR_XML_READER_NULL,
    ERROR_XML_RESPONSE_ERROR,
    ERROR_XML_NAME_ATTR_NOT_FOUND,
    ERROR_XML_ID_ATTR_NOT_FOUND,
    ERROR_XML_TYPE_ATTR_NOT_FOUND,
    ERROR_XML_ALIAS_ATTR_NOT_FOUND,
    ERROR_XML_DD_OBJECT_NOT_FOUND,
    ERROR_XML_DD_SET_OBJECT_NOT_FOUND,
    ERROR_XML_STATUS_ELEM_NOT_FOUND,
    ERROR_XML_MESSAGE_ELEM_NOT_FOUND,
    ERROR_XML_ISNSSERVER_ELEM_NOT_FOUND,
    ERROR_XML_CREATE_BUFFER_FAILED,
    ERROR_XML_CREATE_WRITER_FAILED,
    ERROR_XML_START_DOC_FAILED,
    ERROR_XML_END_DOC_FAILED,
    ERROR_XML_START_ELEMENT_FAILED,
    ERROR_XML_WRITE_ELEMENT_FAILED,
    ERROR_XML_END_ELEMENT_FAILED,
    ERROR_XML_WRITE_ATTRIBUTE_FAILED,
    ERROR_XML_STRDUP_FAILED,
    ERROR_XML_ADD_CHILD_FAILED,
    ERROR_XML_PARSE_MEMORY_FAILED,
    ERROR_XML_XPATH_NEW_CONTEXT_FAILED,
    ERROR_DOOR_CALL_FAILED,
    ERROR_DOOR_OPEN_FAILED,
    ERROR_ISNS_SMF_SERVICE_NOT_ONLINE,
    ERROR_MALLOC_FAILED,
    ERROR_DDMEMBER_NOT_FOUND,
    ERROR_DDSETMEMBER_NOT_FOUND,
    ERROR_DDMEMBER_ALREADY_EXIST,
    ERROR_DDSETMEMBER_ALREADY_EXIST,
    ERROR_OPERATION_NOT_ALLOWED_FOR_DEFAULT_DD,
    ERROR_OPERATION_NOT_ALLOWED_FOR_DEFAULT_DDSET,
    ERROR_DD_NAME_IN_USE,
    ERROR_DDSET_NAME_IN_USE,
    ERROR_SERVER_BUSY,
    ERROR_SERVER_INTERNAL_ERROR,
    UNKNOWN
} msg_code_t;

/* proto type */
char *getTextMessage(msg_code_t code);

#ifdef	__cplusplus
}
#endif

#endif /* _ISNSADM_H */
