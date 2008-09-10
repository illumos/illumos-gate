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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include "lm.h"
#include <lm_proto.h>

static	char	*_SrcFile = __FILE__;

char *lm_priv_set[] =  {
	"LMMessageLevel",
	"TraceLevel",
	"TraceFileSize",
	"SystemDiskMountTimeout",
	NULL };

char *lm_priv_unset[] = {
	"LMMessageLevel",
	"Tracelevel",
	"TraceFileSize",
	"SystemDiskMountTimeout",
	NULL };

char *lm_priv_get[] = {
	NULL };

/*
 * lm_validate_private()
 *
 * Parameters:
 *	- cmd		LMPM private command being processed.
 *	- tid		Task id of private command being processed.
 *	- ret_msg	Ptr to final response string. If an error message is
 *			to be sent to MM for the private command because of
 *			a failure, the response is copied here.
 *
 * Globals:
 *	- lm_priv_set	The set-name values allowed in a LMPM private cmd.
 *	- lm_priv_get	The get-name values allowed in a LMPM private cmd.
 *	- lm_priv_unset	The unset-name values allowed in a LMPM private cmd.
 *
 * This function validates that all the set-name, get-name, and unset-name
 * are valid. If the private command contains a name that is not known by
 * LM, a error final response is sent in response the the LMPM private cmd.
 * This function does not validate that the set-value is valid, while the
 * set-name is being processed, the value needs to be validated.
 *
 * Return Values:
 *	- LM_OK		If all names are valid LM_OK is returned.
 *	- LM_ERROR	If a name is encountered that is not know, LM_ERROR
 *			is returned and ret_msg is updated to reflect the
 *			error final response for the LMPM private cmd.
 */
int
lm_validate_private(mms_par_node_t *cmd, char *tid, char *ret_msg)
{
	int		i;
	mms_par_node_t	*loc = NULL;
	mms_par_node_t	*loc1;
	char		msg_str[256];

	mms_par_node_t	*clause;
	mms_par_node_t	*name;
	mms_par_node_t	*value;

	for (clause = mms_pn_lookup(cmd, "get", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "get",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG, "lm_v_private:, Validating a get clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			for (i = 0; lm_priv_get[i] != NULL; i++) {
				if (strcmp(mms_pn_token(name),
				    lm_priv_get[i]) == 0) {
					mms_trace(MMS_DEBUG,
					    "lm_v_private: private "
					    "get contains %s get-name",
					    mms_pn_token(name));
					break;
				}
			}

			if (lm_priv_get[i] == NULL) {
				mms_trace(MMS_ERR,
				    "lm_v_private: private command "
				    "contains a unsupport get-name - %s",
				    mms_pn_token(name));
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7010_MSG, "type", "get",
				    "name", mms_pn_token(name), NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_EXIST),
				    mms_sym_code_to_str(MMS_LM_E_NOELT),
				    msg_str);
				return (LM_ERROR);
			}

		}
	}

	loc = NULL;
	for (clause = mms_pn_lookup(cmd, "set", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "set",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG, "lm_v_private:, Validating a set clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			for (i = 0; lm_priv_set[i] != NULL; i++) {
				if (strcmp(mms_pn_token(name),
				    lm_priv_set[i]) == 0) {
					mms_trace(MMS_DEBUG,
					    "lm_v_private: private "
					    "set contains %s set-name",
					    mms_pn_token(name));
					break;
				}
			}

			if (lm_priv_set[i] == NULL) {
				mms_trace(MMS_ERR,
				    "lm_v_private: private command "
				    "contains a unsupport set-name - %s",
				    mms_pn_token(name));
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7010_MSG, "type", "set",
				    "name", mms_pn_token(name), NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_EXIST),
				    mms_sym_code_to_str(MMS_LM_E_NOELT),
				    msg_str);
				return (LM_ERROR);
			}

				/* For set clauses, the values asssociated */
				/* with the set-name are validated when */
				/* the set is acutally being processed, */
				/* here just skip them to get next set-name */
			MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING,
			    &loc1);
		}
	}

	loc = NULL;
	for (clause = mms_pn_lookup(cmd, "unset", MMS_PN_CLAUSE, &loc);
	    clause != NULL; clause = mms_pn_lookup(cmd, "unset",
	    MMS_PN_CLAUSE, &loc)) {

		mms_trace(MMS_DEBUG,
		    "lm_v_private:, Validating a unset clause");

		loc1 = NULL;
		for (name = mms_pn_lookup(clause, NULL, MMS_PN_STRING,
		    &loc1); name != NULL; name = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING, &loc1)) {

			for (i = 0; lm_priv_unset[i] != NULL; i++) {
				if (strcmp(mms_pn_token(name),
				    lm_priv_unset[i]) == 0) {
					mms_trace(MMS_DEBUG,
					    "lm_v_private: private "
					    "unset contains %s unset-name",
					    mms_pn_token(name));
					break;
				}
			}

			if (lm_priv_unset[i] == NULL) {
				mms_trace(MMS_ERR,
				    "lm_v_private: private command "
				    "contains a unsupport unset-name - %s",
				    mms_pn_token(name));
				(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
				    LM_7010_MSG, "type", "unset",
				    "name", mms_pn_token(name), NULL);
				(void) snprintf(ret_msg, RMBUFSIZE,
				    LM_ERR_FINAL, tid,
				    mms_sym_code_to_str(MMS_EXIST),
				    mms_sym_code_to_str(MMS_LM_E_NOELT),
				    msg_str);
				return (LM_ERROR);
			}

		}
	}

	return (LM_OK);

not_found:
	mms_trace(MMS_ERR, "lm_v_private: LMPM private command has a "
	    "missing value for a set-name:\n%s",
	    mms_pn_build_cmd_text(cmd));
	(void) mms_buf_msgcl(msg_str, sizeof (msg_str),
	    LM_7009_MSG, "cmd", "private", "part", "set", NULL);
	(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
	    mms_sym_code_to_str(MMS_INVALID),
	    mms_sym_code_to_str(MMS_LM_E_CMDARGS), msg_str);
	return (LM_ERROR);
}
