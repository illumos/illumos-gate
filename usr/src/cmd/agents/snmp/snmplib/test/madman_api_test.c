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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include "stdio.h"
#include "errno.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"

#include "snmp_msg.h"
#include "error.h"
#include "trace.h"
#include "madman_api.h"


/***** NEW CONSTANTS *****/

#define MSG_END_OF_TABLE	"end of table for request %s on %s\n\n"
#define ERR_MSG_REQUEST_FAILED	"the request %s on %s failed: %s\n\n"


/***** NEW TYPES *****/

typedef struct _Target {
	struct _Target *next_target;
	char name[100];
} Target;


/***** STATIC VARIABLES *****/

static int snmp_session_num = 0;

static Target *first_target = NULL;


/****** STATIC FUNCTIONS *****/

static int target_add(char *name, char *error_label);


/**************************************************************/

static int target_add(char *name, char *error_label)
{
	Target *new;


	error_label[0] = '\0';

	if(name == NULL)
	{
		sprintf(error_label, "BUG: name is NULL");
		return -1;
	}

	new = (Target *) malloc(sizeof(Target));
	if(new == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return -1;
	}

	strcpy(new->name, name);

	new->next_target = first_target;
	first_target = new;

	return 0;
}


/**************************************************************/
/*
 *	do not free response!
 */

static void snmp_callback(int operation, SNMP_session *session, int request_id, int predefined_id, SNMP_pdu *response, void *snmp_callback_magic)
{
	struct itimerval itimeout;
	ApplEntry *applEntry = NULL;
	AssocEntry *assocEntry = NULL;
	MtaEntry *mtaEntry = NULL;
	MtaGroupEntry *mtaGroupEntry = NULL;
	MtaGroupAssociationEntry *mtaGroupAssociationEntry = NULL;
	DsaOpsEntry *dsaOpsEntry = NULL;
	DsaEntriesEntry *dsaEntriesEntry = NULL;
	DsaIntEntry *dsaIntEntry = NULL;
	X4msMtaEntry *x4msMtaEntry = NULL;
	X4msUserEntryPart1 *x4msUserEntryPart1 = NULL;
	X4msUserEntryPart2 *x4msUserEntryPart2 = NULL;
	X4msUserAssociationEntry *x4msUserAssociationEntry = NULL;
	X4grpEntry *x4grpEntry = NULL;
	X4grpMappingEntry *x4grpMappingEntry = NULL;
	X5dsaReferenceEntry *x5dsaReferenceEntry = NULL;
	char *request_name = NULL;


	request_name = predefined_request_string(predefined_id);

	switch(operation)
	{
		case RECEIVED_MESSAGE:
			switch(predefined_id)
			{
				case APPL_ENTRY_REQ:
					applEntry = applEntry_process_response(session, response, error_label);
					if(applEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(assocEntry_send_request(session, GETNEXT_REQ_MSG, -1, -1, error_label))
							{
								fprintf(stderr, "assocEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						applEntry_print(applEntry);
						if(applEntry_send_request(session, GETNEXT_REQ_MSG, applEntry->applIndex, error_label))
						{
							fprintf(stderr, "applEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						applEntry_free(applEntry);
					}

					break;


				case ASSOC_ENTRY_REQ:
					assocEntry = assocEntry_process_response(session, response, error_label);
					if(assocEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(mtaEntry_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
							{
								fprintf(stderr, "mtaEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						assocEntry_print(assocEntry);
						if(assocEntry_send_request(session, GETNEXT_REQ_MSG, assocEntry->applIndex, assocEntry->assocIndex, error_label))
						{
							fprintf(stderr, "assocEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						assocEntry_free(assocEntry);
					}

					break;


				case MTA_ENTRY_REQ:
					mtaEntry = mtaEntry_process_response(session, response, error_label);
					if(mtaEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(mtaGroupEntry_send_request(session, GETNEXT_REQ_MSG, -1, -1, error_label))
							{
								fprintf(stderr, "mtaGroupEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						mtaEntry_print(mtaEntry);
						if(mtaEntry_send_request(session, GETNEXT_REQ_MSG, mtaEntry->applIndex, error_label))
						{
							fprintf(stderr, "mtaEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						mtaEntry_free(mtaEntry);
					}

					break;


				case MTA_GROUP_ENTRY_REQ:
					mtaGroupEntry = mtaGroupEntry_process_response(session, response, error_label);
					if(mtaGroupEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(mtaGroupAssociationEntry_send_request(session, GETNEXT_REQ_MSG, -1, -1, -1, error_label))
							{
								fprintf(stderr, "mtaGroupAssociationEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						mtaGroupEntry_print(mtaGroupEntry);
						if(mtaGroupEntry_send_request(session, GETNEXT_REQ_MSG, mtaGroupEntry->applIndex, mtaGroupEntry->mtaGroupIndex, error_label))
						{
							fprintf(stderr, "mtaGroupEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						mtaGroupEntry_free(mtaGroupEntry);
					}

					break;


				case MTA_GROUP_ASSOCIATION_ENTRY_REQ:
					mtaGroupAssociationEntry = mtaGroupAssociationEntry_process_response(session, response, error_label);
					if(mtaGroupAssociationEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(dsaOpsEntry_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
							{
								fprintf(stderr, "dsaOpsEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						mtaGroupAssociationEntry_print(mtaGroupAssociationEntry);
						if(mtaGroupAssociationEntry_send_request(session, GETNEXT_REQ_MSG, mtaGroupAssociationEntry->applIndex, mtaGroupAssociationEntry->mtaGroupIndex, mtaGroupAssociationEntry->mtaGroupAssociationIndex, error_label))
						{
							fprintf(stderr, "mtaGroupAssociationEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						mtaGroupAssociationEntry_free(mtaGroupAssociationEntry);
					}

					break;


				case DSA_OPS_ENTRY_REQ:
					dsaOpsEntry = dsaOpsEntry_process_response(session, response, error_label);
					if(dsaOpsEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(dsaEntriesEntry_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
							{
								fprintf(stderr, "dsaEntriesEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						dsaOpsEntry_print(dsaOpsEntry);
						if(dsaOpsEntry_send_request(session, GETNEXT_REQ_MSG, dsaOpsEntry->applIndex, error_label))
						{
							fprintf(stderr, "dsaOpsEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						dsaOpsEntry_free(dsaOpsEntry);
					}

					break;


				case DSA_ENTRIES_ENTRY_REQ:
					dsaEntriesEntry = dsaEntriesEntry_process_response(session, response, error_label);
					if(dsaEntriesEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(dsaIntEntry_send_request(session, GETNEXT_REQ_MSG, -1, -1, error_label))
							{
								fprintf(stderr, "dsaIntEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						dsaEntriesEntry_print(dsaEntriesEntry);
						if(dsaEntriesEntry_send_request(session, GETNEXT_REQ_MSG, dsaEntriesEntry->applIndex, error_label))
						{
							fprintf(stderr, "dsaEntriesEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						dsaEntriesEntry_free(dsaEntriesEntry);
					}

					break;


				case DSA_INT_ENTRY_REQ:
					dsaIntEntry = dsaIntEntry_process_response(session, response, error_label);
					if(dsaIntEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(x4msMtaEntry_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
							{
								fprintf(stderr, "x4msMtaEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						dsaIntEntry_print(dsaIntEntry);
						if(dsaIntEntry_send_request(session, GETNEXT_REQ_MSG, dsaIntEntry->applIndex, dsaIntEntry->dsaIntIndex, error_label))
						{
							fprintf(stderr, "dsaIntEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						dsaIntEntry_free(dsaIntEntry);
					}

					break;


				case X4MS_MTA_ENTRY_REQ:
					x4msMtaEntry = x4msMtaEntry_process_response(session, response, error_label);
					if(x4msMtaEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(x4msUserEntryPart1_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
							{
								fprintf(stderr, "x4msUserEntryPart1_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						x4msMtaEntry_print(x4msMtaEntry);
						if(x4msMtaEntry_send_request(session, GETNEXT_REQ_MSG, x4msMtaEntry->x4msMtaIndex, error_label))
						{
							fprintf(stderr, "x4msMtaEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						x4msMtaEntry_free(x4msMtaEntry);
					}

					break;


				case X4MS_USER_ENTRY_PART1_REQ:
					x4msUserEntryPart1 = x4msUserEntryPart1_process_response(session, response, error_label);
					if(x4msUserEntryPart1 == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(x4msUserAssociationEntry_send_request(session, GETNEXT_REQ_MSG, -1, -1, error_label))
							{
								fprintf(stderr, "x4msUserAssociationEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						x4msUserEntryPart1_print(x4msUserEntryPart1);

						if(x4msUserEntryPart2_send_request(session, GET_REQ_MSG, x4msUserEntryPart1->x4msUserIndex, error_label))
						{
							fprintf(stderr, "x4msUserEntryPart2_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}

						if(x4msUserEntryPart1_send_request(session, GETNEXT_REQ_MSG, x4msUserEntryPart1->x4msUserIndex, error_label))
						{
							fprintf(stderr, "x4msUserEntryPart1_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}

						x4msUserEntryPart1_free(x4msUserEntryPart1);
					}

					break;


				case X4MS_USER_ENTRY_PART2_REQ:
					x4msUserEntryPart2 = x4msUserEntryPart2_process_response(session, response, error_label);
					if(x4msUserEntryPart2 == NULL)
					{
						fprintf(stderr, ERR_MSG_REQUEST_FAILED,
							request_name, session->peername, error_label);
						trace_snmp_pdu(response);

						snmp_session_close(session, error_label);
						snmp_session_num--;
					}
					else
					{
						x4msUserEntryPart2_print(x4msUserEntryPart2);
						x4msUserEntryPart2_free(x4msUserEntryPart2);
					}

					break;


				case X4MS_USER_ASSOCIATION_ENTRY_REQ:
					x4msUserAssociationEntry = x4msUserAssociationEntry_process_response(session, response, error_label);
					if(x4msUserAssociationEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(x4grpEntry_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
							{
								fprintf(stderr, "x4grpEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						x4msUserAssociationEntry_print(x4msUserAssociationEntry);
						if(x4msUserAssociationEntry_send_request(session, GETNEXT_REQ_MSG, x4msUserAssociationEntry->x4msUserIndex, x4msUserAssociationEntry->x4msUserAssociationIndex, error_label))
						{
							fprintf(stderr, "x4msUserAssociationEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						x4msUserAssociationEntry_free(x4msUserAssociationEntry);
					}

					break;

				case X4GRP_ENTRY_REQ:
					x4grpEntry = x4grpEntry_process_response(session, response, error_label);
					if(x4grpEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(x4grpMappingEntry_send_request(session, GETNEXT_REQ_MSG, -1, -1, -1, error_label))
							{
								fprintf(stderr, "x4grpMappingEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						x4grpEntry_print(x4grpEntry);
						if(x4grpEntry_send_request(session, GETNEXT_REQ_MSG, x4grpEntry->x4grpIndex, error_label))
						{
							fprintf(stderr, "x4grpEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						x4grpEntry_free(x4grpEntry);
					}

					break;


				case X4GRP_MAPPING_ENTRY_REQ:
					x4grpMappingEntry = x4grpMappingEntry_process_response(session, response, error_label);
					if(x4grpMappingEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							if(x5dsaReferenceEntry_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
							{
								fprintf(stderr, "x5dsaReferenceEntry_send_request(%s) failed: %s\n\n",
									session->peername, error_label);
								snmp_session_close(session, error_label);
								snmp_session_num--;
							}
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						x4grpMappingEntry_print(x4grpMappingEntry);
						if(x4grpMappingEntry_send_request(session, GETNEXT_REQ_MSG, x4grpMappingEntry->x4grpIndex, x4grpMappingEntry->x4grpMappingMSIndex, x4grpMappingEntry->x4grpMappingMTAIndex, error_label))
						{
							fprintf(stderr, "x4grpMappingEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						x4grpMappingEntry_free(x4grpMappingEntry);
					}

					break;


				case X5DSA_REFERENCE_ENTRY_REQ:
					x5dsaReferenceEntry = x5dsaReferenceEntry_process_response(session, response, error_label);
					if(x5dsaReferenceEntry == NULL)
					{
						if(snmp_errno == SNMP_ERR_NOSUCHNAME)
						{
							fprintf(stderr, MSG_END_OF_TABLE,
								request_name, session->peername);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						else
						{
							fprintf(stderr, ERR_MSG_REQUEST_FAILED,
								request_name, session->peername, error_label);
							trace_snmp_pdu(response);

							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
					}
					else
					{
						x5dsaReferenceEntry_print(x5dsaReferenceEntry);
						if(x5dsaReferenceEntry_send_request(session, GETNEXT_REQ_MSG, x5dsaReferenceEntry->x5dsaReferenceIndex, error_label))
						{
							fprintf(stderr, "x5dsaReferenceEntry_send_request(%s) failed: %s\n\n",
								session->peername, error_label);
							snmp_session_close(session, error_label);
							snmp_session_num--;
						}
						x5dsaReferenceEntry_free(x5dsaReferenceEntry);
					}

					break;


				default:
					fprintf(stderr, "unknown pdu received %d from %s\n\n",
						predefined_id, session->peername);

					trace_snmp_pdu(response);

					snmp_session_close(session, error_label);
					snmp_session_num--;

					break;
			}

			break;


		case TIMED_OUT:
			switch(predefined_id)
			{
				case APPL_ENTRY_REQ:
				case ASSOC_ENTRY_REQ:
				case MTA_ENTRY_REQ:
				case MTA_GROUP_ENTRY_REQ:
				case MTA_GROUP_ASSOCIATION_ENTRY_REQ:
				case X4MS_MTA_ENTRY_REQ:
				case X4MS_USER_ENTRY_PART1_REQ:
				case X4MS_USER_ENTRY_PART2_REQ:
				case X4MS_USER_ASSOCIATION_ENTRY_REQ:
				case X4GRP_ENTRY_REQ:
				case X4GRP_MAPPING_ENTRY_REQ:
				case X5DSA_REFERENCE_ENTRY_REQ:
					fprintf(stderr, "the request %s on %s TIMED OUT\n\n",
						request_name, session->peername);
					break;

				default:
					fprintf(stderr, "an unknown request %d on %s TIMED OUT\n\n",
						predefined_id, session->peername);
					break;
			}

			snmp_session_close(session, error_label);
			snmp_session_num--;

			break;
	}

	if(snmp_session_num == 0)
	{
		exit(0);
	}
}


/**************************************************************/

main(int argc, char **argv)
{
	int numfds;
	fd_set fdset;
	int count;
	struct timeval timeout;
	char targets[1000];
	char target[1000];
	char c;
	char *ptr;
	int i = 0;
	Target *t;


	while((c = getopt(argc, argv, "t:v"))!= -1)
	{
		switch(c)
		{
			case 't':
				strcpy(targets, optarg);
				break;
			case 'v':
				trace_flags = 0xFFFF;
		}
	}


	i = 0;
	for(ptr = targets; *ptr; ptr++)
	{
		if(isspace(*ptr))
		{
			if(i == 0)
			{
				continue;
			}
		}

		target[i++] = *ptr;

		if( (*(ptr + 1) == '\0') || isspace(*(ptr + 1)) )
		{
			target[i] = '\0';

			if(target_add(target, error_label))
			{
				fprintf(stderr, "target_add(%s) failed: %s\n\n",
					target, error_label);
			}

			i = 0;
		}
	}


	for(t = first_target; t; t = t->next_target)
	{
		SNMP_session *session;


		session = snmp_session_open_default(t->name, snmp_callback, NULL, error_label);
		if(session == NULL)
		{
			fprintf(stderr, "snmp_session_open_default(%s) failed: %s\n\n",
				t->name, error_label);
			continue;
		}
		snmp_session_num++;

		if(applEntry_send_request(session, GETNEXT_REQ_MSG, -1, error_label))
		{
			fprintf(stderr, "applEntry_send_request(%s) failed: %s\n\n",
				session->peername, error_label);
			snmp_session_close(session, error_label);
			snmp_session_num--;
		}
	}


	if(snmp_session_num == 0)
	{
		exit(0);
	}


	while(1)
	{
		numfds = 0;
		FD_ZERO(&fdset);

		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		snmp_session_select_info(&numfds, &fdset, &timeout);

		count = select(numfds, &fdset, 0, 0, &timeout);
		if(count > 0)
		{
			snmp_session_read(&fdset);
		}
		else
		{
			switch(count)
			{
				case 0:
					snmp_session_timeout();
					break;

				case -1:
					if(errno == EINTR)
					{
						continue;
					}
					else
					{
						fprintf(stderr, "select() failed %s\n",
							errno_string());
					}
			}
		}
	}
}


