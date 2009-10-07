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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <utility.h>
#include <fcntl.h>
#include <syslog.h>

#include <iscsitgt_impl.h>
#include "target.h"
#include "utility.h"
#include "errcode.h"
#include "isns_client.h"
#include <sys/scsi/generic/commands.h>
#include "mgmt_scf.h"
#include "t10_spc.h"

#define	CRC32_STR	"CRC32C"
#define	NONE_STR	"None"

static thick_provo_t	*thick_head,
			*thick_tail;
pthread_mutex_t		thick_mutex;

static Boolean_t connection_parameters_get(iscsi_conn_t *c, char *targ_name);
static Boolean_t util_create_guid_naa(char **guid);

void
util_init()
{
	(void) pthread_mutex_init(&thick_mutex, NULL);
}

/*
 * []----
 * | check_access -- see if the requesting initiator is in the ACL
 * |
 * | Optionally will also check to see if this initiator requires
 * | authentication.
 * []----
 */
Boolean_t
check_access(tgt_node_t *targ, char *initiator_name, Boolean_t req_chap)
{
	tgt_node_t	*acl;
	tgt_node_t	*inode		= NULL;
	tgt_node_t	*tgt_initiator	= NULL;
	char		*dummy;
	Boolean_t	valid		= False;
	Boolean_t	found_chap	= False;
	Boolean_t	access		= False;

	/*
	 * If ISNS is enable check for access privilege from isns server
	 */
	if (isns_enabled() == True) {
		if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &dummy)
		    == False) {
			return (False);
		}
		access = isns_qry_initiator(dummy, initiator_name);
		free(dummy);
		if (req_chap == False) {
			return (access);
		}

		/* Need to check if CHAP is needed for initiator */
		while ((inode = tgt_node_next_child(main_config,
		    XML_ELEMENT_INIT, inode)) != NULL) {
			if (tgt_find_value_str(inode, XML_ELEMENT_INAME, &dummy)
			    == True) {
				if (strcmp(dummy, initiator_name) == 0) {
					free(dummy);
					if (tgt_find_value_str(inode,
					    XML_ELEMENT_CHAPSECRET, &dummy)
					    == True) {
						free(dummy);
						found_chap = True;
						break;
					}
				}
			}
		}
		if (access == True) {
			if ((req_chap == True) && (found_chap == True))
				access = False;
		}
		return (access);
	}

	/*
	 * If there's no ACL for this target everyone has access.
	 */
	if ((acl = tgt_node_next(targ, XML_ELEMENT_ACLLIST, NULL)) == NULL)
		return (True);

	/*
	 * Find the local initiator name and also save the knowledge
	 * if the initiator had a CHAP secret.
	 */
	inode = NULL;
	while ((inode = tgt_node_next_child(main_config, XML_ELEMENT_INIT,
	    inode)) != NULL) {
		if (tgt_find_value_str(inode, XML_ELEMENT_INAME, &dummy) ==
		    True) {
			if (strcmp(dummy, initiator_name) == 0) {
				free(dummy);
				if (tgt_find_value_str(inode,
				    XML_ELEMENT_CHAPSECRET, &dummy) == True) {
					free(dummy);
					found_chap = True;
				}
				break;
			} else {
				free(dummy);
			}
		}
	}

	if ((acl != NULL) && (inode == NULL))
		return (False);

	while ((tgt_initiator = tgt_node_next(acl, XML_ELEMENT_INIT,
	    tgt_initiator)) != NULL) {

		if (strcmp(inode->x_value, tgt_initiator->x_value) == 0) {
			valid = True;
			break;
		}
	}

	if (valid == True) {

		/*
		 * If req_chap is True it means the login code hasn't gone
		 * through the authentication phase and it's trying to
		 * determine if the initiator should have done so. If
		 * we find a CHAP-secret then this routine will fail.
		 * No CHAP-secret for an initiator just means that a
		 * simple ACL list is used. This can be spoofed easily
		 * enough and is mainly used to limit the number of
		 * targets an initiator would see.
		 */
		if ((req_chap == True) && (found_chap == True))
			valid = False;
	}

	return (valid);
}

/*
 * []----
 * | convert_local_tpgt -- Convert a local tpgt name to real addresses
 * |
 * | To simplify the configuration files targets only have a target portal
 * | group tag string(s) associated. In the main configuration file there's
 * | a tpgt element which has one or more ip-address elements. So the tag
 * | is located and the actual data is inserted into the outgoing stream.
 * []----
 */
static Boolean_t
convert_local_tpgt(char **text, int *text_length, char *local_tpgt)
{
	tgt_node_t	*tpgt	= NULL;
	tgt_node_t 	*x;
	char		buf[80];
	char		ipaddr[4];

	while ((tpgt = tgt_node_next_child(main_config, XML_ELEMENT_TPGT,
	    tpgt)) != NULL) {
		if (strcmp(tpgt->x_value, local_tpgt) == 0) {

			/*
			 * The only children of the tpgt element are
			 * ip-address elements. The value of each element is
			 * the string we need to use. So, we don't need to
			 * check the node's name to see if this is correct or
			 * not.
			 */
			if ((tpgt = tgt_node_next(tpgt, XML_ELEMENT_IPADDRLIST,
			    NULL)) == NULL) {
				return (False);
			}

			x = NULL;
			while ((x = tgt_node_next(tpgt, XML_ELEMENT_IPADDR, x))
			    != NULL) {
				if (inet_pton(AF_INET, x->x_value, &ipaddr)
				    == 1) {
					/*
					 * Valid IPv4 address
					 */
					(void) snprintf(buf, sizeof (buf),

					    "%s,%s", x->x_value, local_tpgt);
				} else {
					/*
					 * Invalid IPv4 address
					 * try with brackets (RFC2732)
					 */
					(void) snprintf(buf, sizeof (buf),
					    "[%s],%s", x->x_value, local_tpgt);
				}
				(void) add_text(text, text_length,
				    "TargetAddress", buf);
			}
			break;
		}
	}

	return (True);
}

/*
 * []----
 * | add_target_address -- find and add any target address information
 * []----
 */
static void
add_target_address(iscsi_conn_t *c, char **text, int *text_length,
    tgt_node_t *targ)
{
	tgt_node_t	*tpgt_list;
	tgt_node_t	*tpgt = NULL;
	struct sockaddr_in	*sp4;
	struct sockaddr_in6	*sp6;
	/*
	 * 7 is enough room for the largest TPGT of "65536", the ',' and a NULL
	 */
	char	buf[INET6_ADDRSTRLEN + 7];
	char	net_buf[INET6_ADDRSTRLEN];

	if ((tpgt_list = tgt_node_next(targ, XML_ELEMENT_TPGTLIST,
	    NULL)) == NULL) {
		if_target_address(text, text_length,
		    (struct sockaddr *)&c->c_target_sockaddr);
		return;
	}

	while ((tpgt = tgt_node_next_child(tpgt_list, XML_ELEMENT_TPGT,
	    tpgt)) != NULL) {
		if (convert_local_tpgt(text, text_length, tpgt->x_value) ==
		    False) {
			if (c->c_target_sockaddr.ss_family == AF_INET) {
				sp4 = (struct sockaddr_in *)
				    &c->c_target_sockaddr;
				(void) snprintf(buf, sizeof (buf), "%s,%s",
				    inet_ntop(sp4->sin_family,
				    (void *)&sp4->sin_addr,
				    net_buf, sizeof (net_buf)),
				    tpgt->x_value);
			} else {
				sp6 = (struct sockaddr_in6 *)
				    &c->c_target_sockaddr;
				(void) snprintf(buf, sizeof (buf), "[%s],%s",
				    inet_ntop(sp6->sin6_family,
				    (void *)&sp6->sin6_addr,
				    net_buf, sizeof (net_buf)),
				    tpgt->x_value);
			}
			(void) add_text(text, text_length, "TargetAddress",
			    buf);
		}
	}
}

/*
 * []----
 * | add_targets -- add TargetName and TargetAddress to text argument
 * |
 * | Add targets which this initiator is allowed to see based on
 * | the access_list associated with a target. If a target doesn't
 * | have an access list then let everyone see it.
 * []----
 */
static Boolean_t
add_targets(iscsi_conn_t *c, char **text, int *text_length)
{
	tgt_node_t	*targ		= NULL;
	Boolean_t	rval		= True;
	char		*targ_name	= NULL;

	while ((rval == True) && ((targ = tgt_node_next_child(targets_config,
	    XML_ELEMENT_TARG, targ)) != NULL)) {

		if (check_access(targ, c->c_sess->s_i_name, False) == True) {

			if (tgt_find_value_str(targ, XML_ELEMENT_INAME,
			    &targ_name) == False) {
				rval = False;
				break;
			}
			queue_prt(c->c_mgmtq, Q_CONN_LOGIN,
			    "CON%x    %24s = %s\n", c->c_num, "TargetName",
			    targ_name);

			(void) add_text(text, text_length, "TargetName",
			    targ_name);
			free(targ_name);
			add_target_address(c, text, text_length, targ);
		}
	}
	return (rval);
}

/*
 * []----
 * | add_text -- Add new name/value pair to possibly existing string
 * []----
 */
Boolean_t
add_text(char **text, int *current_length, char *name, char *val)
{
	int	dlen = *current_length;
	int	plen;
	char	*p;

	/*
	 * Length is 'name' + separator + 'value' + NULL
	 */
	plen = strlen(name) + 1 + strlen(val) + 1;

	if (dlen) {
		if ((p = (char *)realloc(*text, dlen + plen)) == NULL)
			return (False);
	} else {
		if ((p = (char *)malloc(plen)) == NULL)
			return (False);
	}

	*text = p;
	p = *text + dlen;

	(void) snprintf(p, plen, "%s%c%s", name, ISCSI_TEXT_SEPARATOR, val);
	*current_length = dlen + plen;

	return (True);
}

static void
send_named_msg(iscsi_conn_t *c, msg_type_t t, char *name)
{
	target_queue_t	*q = queue_alloc();
	msg_t		*m;
	name_request_t	n;

	n.nr_q		= q;
	n.nr_name	= name;

	queue_message_set(c->c_sessq, 0, t, &n);
	m = queue_message_get(q);
	queue_message_free(m);
	queue_free(q, NULL);
}

static Boolean_t
parse_digest_vals(Boolean_t *bp, char *name, char *val, char **text, int *len)
{
	Boolean_t	rval;

	/*
	 * It's the initiators data so we'll allow them
	 * to determine if CRC checks should be enabled
	 * or not. So, look at the first token, which
	 * declares their preference, and use that.
	 */
	if (strncmp(val, CRC32_STR, strlen(CRC32_STR)) == 0) {
		*bp = True;
		rval = add_text(text, len, name, CRC32_STR);
	} else if (strncmp(val, NONE_STR, strlen(NONE_STR)) == 0) {
		*bp = False;
		rval = add_text(text, len, name, NONE_STR);
	} else {
		*bp = False;
		rval = add_text(text, len, name, "Reject");
	}

	return (rval);
}

/*
 * []----
 * | parse_text -- receive text information from initiator and parse
 * |
 * | Read in the current data based on the amount which the login PDU says
 * | should be available. Add it to the end of previous data if it exists.
 * | Previous data would be from a PDU which had the 'C' bit set and was
 * | stored in the connection.
 * |
 * | Once values for parameter name has been selected store outgoing string
 * | in text message for response.
 * |
 * | If errcode is non-NULL the appropriate login error code will be
 * | stored.
 * []----
 */
Boolean_t
parse_text(iscsi_conn_t *c, int dlen, char **text, int *text_length,
    int *errcode)
{
	char		*p		= NULL;
	char		*n;
	char		*cur_pair;
	char		param_rsp[32];
	int		plen;		/* pair length */
	Boolean_t	rval		= True;
	char		*target_name    = NULL;
	char		*initiator_name = NULL;
	char		param_buf[16];

	if ((p = (char *)malloc(dlen)) == NULL)
		return (False);

	/*
	 * Read in data to buffer.
	 */
	if (read(c->c_fd, p, dlen) != dlen) {
		free(p);
		return (False);
	}

	queue_prt(c->c_mgmtq, Q_CONN_NONIO, "CON%x  Available text size %d\n",
	    c->c_num, dlen);

	/*
	 * Read in and toss any pad data
	 */
	if (dlen % ISCSI_PAD_WORD_LEN) {
		char junk[ISCSI_PAD_WORD_LEN];
		int pad_len = ISCSI_PAD_WORD_LEN - (dlen % ISCSI_PAD_WORD_LEN);

		if (read(c->c_fd, junk, pad_len) != pad_len) {
			free(p);
			return (False);
		}
	}

	if (c->c_text_area != NULL) {
		if ((n = (char *)realloc(c->c_text_area,
		    c->c_text_len + dlen)) == NULL) {
			free(p);
			return (False);
		}
		bcopy(p, n + c->c_text_len, dlen);

		/*
		 * No longer need the space allocated to 'p' since it
		 * will point to the aggregated area of all data.
		 */
		free(p);

		/*
		 * Point 'p' to this new area for parsing and save the
		 * combined length in dlen.
		 */
		p = n;
		dlen += c->c_text_len;

		/*
		 * Clear the indication that space has been allocated
		 */
		c->c_text_area = NULL;
		c->c_text_len = 0;
	}

	/*
	 * At this point 'p' points to the name/value parameters. Need
	 * to cycle through each pair.
	 */
	n = p;
	while (dlen > 0) {
		cur_pair = n;

		plen = strlen(n);
		if ((n = strchr(cur_pair, ISCSI_TEXT_SEPARATOR)) == NULL) {
			if (errcode != NULL)
				*errcode =
				    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
				    ISCSI_LOGIN_STATUS_INIT_ERR;
			rval = False;
			break;
		} else
			*n++ = '\0';

		queue_prt(c->c_mgmtq, Q_CONN_LOGIN, "CON%x    %-24s = %s\n",
		    c->c_num, cur_pair, n);

		/*
		 * At this point, 'cur_pair' points at the name and 'n'
		 * points at the value.
		 */

		/*
		 * []--------------------------------------------------[]
		 * | The order of parameters processed matches the	|
		 * | the RFC in section 12.				|
		 * []--------------------------------------------------[]
		 */
		/*
		 * 12.1 -- HeaderDigest
		 * Negotiated
		 */
		if (strcmp("HeaderDigest", cur_pair) == 0) {

			rval = parse_digest_vals(&c->c_header_digest,
			    cur_pair, n, text, text_length);

		/*
		 * 12.1 -- DataDigest
		 * Negotiated
		 */
		} else if (strcmp("DataDigest", cur_pair) == 0) {

			rval = parse_digest_vals(&c->c_data_digest, cur_pair,
			    n, text, text_length);

		/*
		 * 12.2 -- MaxConnections
		 * Negotiated
		 */
		} else if (strcmp("MaxConnections", cur_pair) == 0) {

			/* ---- To be fixed ---- */
			c->c_max_connections = 1;
			(void) snprintf(param_rsp, sizeof (param_rsp),
			    "%d", c->c_max_connections);
			rval = add_text(text, text_length,
			    cur_pair, param_rsp);

		/*
		 * 12.3 -- SendTargets
		 * Declarative
		 */
		} else if (strcmp("SendTargets", cur_pair) == 0) {

			if ((c->c_sess->s_type != SessionDiscovery) &&
			    (strcmp("All", n) == 0)) {
				rval = add_text(text, text_length, cur_pair,
				    "Irrelevant");
			} else {
				rval = add_targets(c, text, text_length);
			}

		/*
		 * 12.4 -- TargetName
		 * Declarative
		 */
		} else if (strcmp("TargetName", cur_pair) == 0) {

			send_named_msg(c, msg_target_name, n);
			target_name = n;

		/*
		 * 12.5 -- IntiatorName
		 * Declarative
		 */
		} else if (strcmp("InitiatorName", cur_pair) == 0) {

			send_named_msg(c, msg_initiator_name, n);
			initiator_name = n;

		/* ---- Section 12.6 is handled within TargetName ---- */

		/*
		 * 12.7 -- InitiatorAlias
		 * Declarative
		 */
		} else if (strcmp("InitiatorAlias", cur_pair) == 0) {

			send_named_msg(c, msg_initiator_alias, n);

		/*
		 * Sections 12.8 (TargetAddress) and 12.9
		 * (TargetPortalGroupTag) are handled during the SendTargets
		 * processing.
		 */

		/*
		 * 12.10 -- IntialR2T
		 * Negotiated
		 */
		} else if (strcmp("InitialR2T", cur_pair) == 0) {

			c->c_initialR2T = True;
			rval = add_text(text, text_length, cur_pair, "Yes");

		/*
		 * 12.11 -- ImmediateData
		 * Negotiated
		 */
		} else if (strcmp("ImmediateData", cur_pair) == 0) {

			/*
			 * Since we can handle immediate data without
			 * a problem just echo back what the initiator
			 * sends. If the initiator decides to violate
			 * the spec by sending immediate data even though
			 * they've disabled it, it's their problem and
			 * we'll deal with the data.
			 */
			c->c_immediate_data = strcmp(n, "No") ? True : False;
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.12 -- MaxRecvDataSegmentLength
		 * Declarative
		 */
		} else if (strcmp("MaxRecvDataSegmentLength", cur_pair) == 0) {

			c->c_max_recv_data = strtol(n, NULL, 0);
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.13 -- MaxBurstLength
		 * Negotiated
		 */
		} else if (strcmp("MaxBurstLength", cur_pair) == 0) {

			c->c_max_burst_len = strtol(n, NULL, 0);
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.14 -- FirstBurstLength
		 * Negotiated
		 */
		} else if (strcmp("FirstBurstLength", cur_pair) == 0) {

			/*
			 * We can handle anything the initiator wishes
			 * to shove in our direction. So, store the value
			 * in case we ever wish to validate input data,
			 * but there's no real need to do so.
			 */
			c->c_first_burst_len = strtol(n, NULL, 0);
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.15 DefaultTime2Wait
		 * Negotiated
		 */
		} else if (strcmp("DefaultTime2Wait", cur_pair) == 0) {

			c->c_default_time_2_wait = strtol(n, NULL, 0);
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.16 -- DefaultTime2Retain
		 * Negotiated
		 */
		} else if (strcmp("DefaultTime2Retain", cur_pair) == 0) {

			c->c_default_time_2_retain = strtol(n, NULL, 0);
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.17 -- MaxOutstandingR2T
		 * Negotiated
		 */
		} else if (strcmp("MaxOutstandingR2T", cur_pair) == 0) {

			/*
			 * Save the value, but at most we'll toss out
			 * one R2T packet.
			 */
			c->c_max_outstanding_r2t = strtol(n, NULL, 0);
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.18 -- DataPDUInOder
		 * Negotiated
		 */
		} else if (strcmp("DataPDUInOrder", cur_pair) == 0) {

			/*
			 * We can handle DataPDU's out of order and
			 * currently we'll only send them in order. We're
			 * to far removed from the hardware to see data
			 * coming off of the platters out of order so
			 * it's unlikely we'd ever implement this feature.
			 * Store the parameter and echo back the initiators
			 * request.
			 */
			c->c_data_pdu_in_order = strcmp(n, "Yes") == 0 ?
			    True : False;
			rval = add_text(text, text_length, cur_pair, n);

		/*
		 * 12.19 -- DataSequenceInOrder
		 * Negotiated
		 */
		} else if (strcmp("DataSequenceInOrder", cur_pair) == 0) {

			/*
			 * Currently we're set up to look at and require
			 * PDU sequence numbers be in order. The check
			 * now is only done as a prelude to supporting
			 * MC/S and guaranteeing the order of incoming
			 * packets on different connections.
			 */
			c->c_data_sequence_in_order = True;
			rval = add_text(text, text_length, cur_pair, "Yes");

		/*
		 * 12.20 -- ErrorRecoveryLevel
		 * Negotiated
		 */
		} else if (strcmp("ErrorRecoveryLevel", cur_pair) == 0) {

			c->c_erl = 0;
			(void) snprintf(param_rsp, sizeof (param_rsp),
			    "%d", c->c_erl);
			rval = add_text(text, text_length,
			    cur_pair, param_rsp);

		/*
		 * 12.21 -- SessionType
		 * Declarative
		 */
		} else if (strcmp("SessionType", cur_pair) == 0) {

			c->c_sess->s_type = strcmp(n, "Discovery") == 0 ?
			    SessionDiscovery : SessionNormal;


		/*
		 * Appendix A 3.1 -- IFMarker
		 * Negotiated
		 */
		} else if (strcmp("IFMarker", cur_pair) == 0) {

			c->c_ifmarker = False;
			rval = add_text(text, text_length, cur_pair, "No");

		/*
		 * Appendix A 3.1 -- OFMarker
		 * Negotiated
		 */
		} else if (strcmp("OFMarker", cur_pair) == 0) {

			c->c_ofmarker = False;
			rval = add_text(text, text_length, cur_pair, "No");

		} else if ((strcmp("AuthMethod", cur_pair) == 0) ||
		    (strcmp("CHAP_A", cur_pair) == 0) ||
		    (strcmp("CHAP_I", cur_pair) == 0) ||
		    (strcmp("CHAP_C", cur_pair) == 0) ||
		    (strcmp("CHAP_N", cur_pair) == 0) ||
		    (strcmp("CHAP_R", cur_pair) == 0)) {

			rval = add_text(&(c->auth_text), &c->auth_text_length,
			    cur_pair, n);

		} else {

			/*
			 * It's perfectly legitimate for an initiator to
			 * send us a parameter we don't currently understand.
			 * For example, an initiator that supports iSER will
			 * send an RDMA options parameter. If we respond with
			 * a valid return value it knows to switch to iSER
			 * for future processing.
			 */
			rval = add_text(text, text_length,
			    cur_pair, "NotUnderstood");

			/*
			 * Go ahead a log this information in case we see
			 * something unexpected.
			 */
			queue_prt(c->c_mgmtq, Q_CONN_ERRS,
			    "CON%x  Unknown parameter %s=%s\n",
			    c->c_num, cur_pair, n);
		}

		/*
		 * If parsed both Initiator and Target names have been parsed,
		 * then it is now time to load the connection parameters.
		 *
		 * This may fail because the target doesn't exist or the
		 * initiator doesn't have permission to access this target.
		 */
		if ((target_name != NULL) && (initiator_name != NULL)) {
			if ((rval = connection_parameters_get(c, target_name))
			    == False) {
				if ((errcode != NULL) && (*errcode == 0))
					*errcode =
					    (ISCSI_STATUS_CLASS_INITIATOR_ERR
					    << 8) |
					    ISCSI_LOGIN_STATUS_TGT_FORBIDDEN;
			} else if ((rval = add_text(text, text_length,
			    "TargetAlias", c->c_targ_alias)) == True) {

				/*
				 * Add TPGT now
				 */
				(void) snprintf(param_buf, sizeof (param_buf),
				    "%d", c->c_tpgt);
				rval = add_text(text, text_length,
				    "TargetPortalGroupTag", param_buf);
				target_name = initiator_name = NULL;
			}
		}

		if (rval == False) {
			/*
			 * Make sure the caller wants error status and that it
			 * hasn't already been set.
			 */
			if ((errcode != NULL) && (*errcode == 0))
				*errcode =
				    (ISCSI_STATUS_CLASS_TARGET_ERR << 8) |
				    ISCSI_LOGIN_STATUS_TARGET_ERROR;
			break;
		}

		/*
		 * next pair of parameters. 1 is added to include the NULL
		 * byte and the end of each string.
		 */
		n = cur_pair + plen + 1;
		dlen -= (plen + 1);
	}

	if (p != NULL)
		free(p);

	return (rval);
}

/*
 * Pre-seed connection parameters to default values
 * See RFC 3720 Section 12
 */
void
connection_parameters_default(iscsi_conn_t *c)
{
	c->c_max_connections = 1;		/* MaxConnections */
	c->c_tpgt = 1;				/* TargetPortalGroupTag */
	c->c_initialR2T = True;			/* InitialR2T */
	c->c_immediate_data = True;		/* ImmediateData */
	c->c_max_recv_data = 8192;		/* MaxRecvDataSegmentLength */
	c->c_max_burst_len = 262144;		/* MaxBurstLength */
	c->c_first_burst_len = 65536;		/* FirstBurstLength */
	c->c_default_time_2_wait = 2;		/* DefaultTime2Wait */
	c->c_default_time_2_retain = 20;	/* DefaultTime2Retain */
	c->c_max_outstanding_r2t = 1;		/* MaxOutStandingR2T */
	c->c_data_pdu_in_order = True;		/* DataPDUInOrder */
	c->c_data_sequence_in_order = True;	/* DataSequenceOrder */
	c->c_erl = 0;				/* ErrorRecoveryLevel */
}

/*
 * []----
 * | find_main_tpgt -- Looks up the IP address and finds a match TPGT
 * |
 * | If no TPGT for this address exists the routine returns 0 which
 * | is an illegal TPGT value.
 * []----
 */
static int
find_main_tpgt(struct sockaddr_storage *pst)
{
	char		ip_addr[16];
	tgt_node_t	*tpgt				= NULL;
	tgt_node_t	*ip_node			= NULL;
	struct in_addr	addr;
	struct in6_addr	addr6;

	/*
	 * Hardly can you believe that such struct-to-struct
	 * assignment IS valid.
	 */
	addr = ((struct sockaddr_in *)pst)->sin_addr;
	addr6 = ((struct sockaddr_in6 *)pst)->sin6_addr;

	while ((tpgt = tgt_node_next_child(main_config, XML_ELEMENT_TPGT,
	    tpgt)) != NULL) {

		ip_node = NULL;
		while ((ip_node = tgt_node_next(tpgt, XML_ELEMENT_IPADDR,
		    ip_node)) != NULL) {

			if (pst->ss_family == AF_INET) {

				if (inet_pton(AF_INET, ip_node->x_value,
				    ip_addr) != 1) {
					continue;
				}
				if (bcmp(ip_addr, &addr,
					sizeof (struct in_addr)) == 0) {
					return (atoi(tpgt->x_value));
				}
			} else if (pst->ss_family == AF_INET6) {

				if (inet_pton(AF_INET6, ip_node->x_value,
				    ip_addr) != 1) {
					continue;
				}
				if (bcmp(ip_addr, &addr6,
					sizeof (struct in6_addr)) == 0) {
					return (atoi(tpgt->x_value));
				}
			}
		}
	}

	return (0);
}

/*
 * convert_to_tpgt -- return a TPGT based on the target address
 *
 * If a target doesn't have a TPGT list then just return the default
 * value of 1. Otherwise determine which TPGT the target address is
 * part of and find that TPGT value in the list of TPGTs this target
 * is willing to expose. If the TPGT value is not found in the list
 * return zero which will break the connection.
 */
static int
convert_to_tpgt(iscsi_conn_t *c, tgt_node_t *targ)
{
	tgt_node_t	*list;
	tgt_node_t	*tpgt		= NULL;
	int		addr_tpgt, pos_tpgt;

	/*
	 * If this target doesn't have a list of target portal group tags
	 * just return the default which is 1.
	 */
	list = tgt_node_next(targ, XML_ELEMENT_TPGTLIST, NULL);
	if (list == NULL)
		return (1);

	/*
	 * If we don't find our IP in the general configuration list
	 * we'll use the default value which is 1 according to RFC3720.
	 */
	addr_tpgt = find_main_tpgt(&(c->c_target_sockaddr));

	while ((tpgt = tgt_node_next(list, XML_ELEMENT_TPGT, tpgt)) != NULL) {
		(void) tgt_find_value_int(tpgt, XML_ELEMENT_TPGT, &pos_tpgt);
		if (pos_tpgt == addr_tpgt) {
			return (addr_tpgt);
		}
	}

	return (0);
}

/*
 * []----
 * | find_target_node -- given a target IQN name, return the XML node
 * []----
 */
tgt_node_t *
find_target_node(char *targ_name)
{
	tgt_node_t	*tnode	= NULL;
	char		*iname;

	while ((tnode = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    tnode)) != NULL) {
		if (tgt_find_value_str(tnode, XML_ELEMENT_INAME, &iname) ==
		    True) {
			if (strcmp(iname, targ_name) == 0) {
				free(iname);
				return (tnode);
			} else
				free(iname);
		}
	}

	return (NULL);
}

static Boolean_t
connection_parameters_get(iscsi_conn_t *c, char *targ_name)
{
	tgt_node_t	*targ, *alias;
	Boolean_t	rval	= False;

	(void) pthread_rwlock_rdlock(&targ_config_mutex);
	if ((targ = find_target_node(targ_name)) != NULL) {

		if (check_access(targ, c->c_sess->s_i_name, False) == False) {
			(void) pthread_rwlock_unlock(&targ_config_mutex);
			return (False);
		}

		/*
		 * Have a valid node for our target. Start looking
		 * for connection oriented parameters.
		 */
		if ((c->c_tpgt = convert_to_tpgt(c, targ)) == 0) {
			(void) pthread_rwlock_unlock(&targ_config_mutex);
			return (False);
		}
		if ((alias = tgt_node_next(targ, XML_ELEMENT_ALIAS, NULL)) ==
		    NULL) {
			(void) tgt_find_value_str(targ, XML_ELEMENT_TARG,
			    &c->c_targ_alias);
		} else {
			(void) tgt_find_value_str(alias, XML_ELEMENT_ALIAS,
			    &c->c_targ_alias);
		}

		(void) tgt_find_value_int(targ, XML_ELEMENT_MAXCMDS,
		    &c->c_maxcmdsn);
		rval = True;
	}

	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (rval);
}

Boolean_t
validate_version(tgt_node_t *node, int *maj_p, int *min_p)
{
	char	*vers_str	= NULL;
	char	*minor_part;
	int	maj, min;

	if ((tgt_find_attr_str(node, XML_ELEMENT_VERS, &vers_str) == False) ||
	    (vers_str == NULL))
		return (False);

	maj = strtol(vers_str, &minor_part, 0);
	if ((maj > *maj_p) || (minor_part == NULL) || (*minor_part != '.')) {
		free(vers_str);
		return (False);
	}

	min	= strtol(&minor_part[1], NULL, 0);
	*maj_p	= maj;
	*min_p	= min;
	free(vers_str);

	return (True);
}

/*
 * []----
 * | sna_lt -- Serial Number Arithmetic, 32 bits, less than, RFC1982
 * []----
 */
int
sna_lt(uint32_t n1, uint32_t n2)
{
	return ((n1 != n2) &&
	    (((n1 < n2) && ((n2 - n1) < SNA32_CHECK)) ||
	    ((n1 > n2) && ((n1 - n2) > SNA32_CHECK))));
}

/*
 * []----
 * sna_lte -- Serial Number Arithmetic, 32 bits, less than, RFC1982
 * []----
 */
int
sna_lte(uint32_t n1, uint32_t n2)
{
	return ((n1 == n2) ||
	    (((n1 < n2) && ((n2 - n1) < SNA32_CHECK)) ||
	    ((n1 > n2) && ((n1 - n2) > SNA32_CHECK))));
}

/*
 * util_create_guid -- generate GUID based on the guid type
 * id_type:	SPC_INQUIRY_ID_TYPE_EUI -
 *		EUI-64 based 16-byte designator format;
 *		SPC_INQUIRY_ID_TYPE_NAA -
 *		NAA IEEE Registered Extended designator format.
 *
 * SPC-4 revision 11 section 7.6.3.5.4 and 7.6.3.6.5.
 *
 * Note that now this function is always called with parameter
 * id_type SPC_INQUIRY_ID_TYPE_NAA, therefore the code for creating
 * EUI-64 based 16-byte format GUID is no longer used. But in order
 * to keep backward compatiability and for future extension, all the
 * code that has been used for creating old GUIDs should be kept, to
 * make the format clear for all possible GUIDs targets might have.
 */
Boolean_t
util_create_guid(char **guid, uchar_t id_type)
{
	eui_16_t	eui;
	/*
	 * We only have room for 32bits of data in the GUID. The hiword/loword
	 * macros will not work on 64bit variables. The work, but produce
	 * invalid results on Big Endian based machines.
	 */
	uint32_t	tval = (uint_t)time((time_t *)0);
	size_t		guid_size;
	int		i, fd;

	/*
	 * Create the NAA (6) GUID.
	 */
	if (id_type == SPC_INQUIRY_ID_TYPE_NAA) {
		return (util_create_guid_naa(guid));
	}

	if ((mac_len == 0) && (if_find_mac(NULL) == False)) {

		/*
		 * By default strict GUID generation is enforced. This can
		 * be disabled by using the correct XML tag in the configuration
		 * file.
		 */
		if (enforce_strict_guid == True)
			return (False);

		/*
		 * There's no MAC address available and we've even tried
		 * a second time to get one. So fallback to using a random
		 * number for the MAC address.
		 */
		if ((fd = open("/dev/random", O_RDONLY)) < 0)
			return (False);
		if (read(fd, &eui, sizeof (eui)) != sizeof (eui))
			return (False);
		(void) close(fd);

		eui.e_vers		= SUN_EUI_16_VERS;
		eui.e_company_id[0]	= (SUN_EN >> 16) & 0xff;
		eui.e_company_id[1]	= (SUN_EN >> 8) & 0xff;
		eui.e_company_id[2]	= SUN_EN & 0xff;

	} else {
		bzero(&eui, sizeof (eui));

		eui.e_vers	= SUN_EUI_16_VERS;
		eui.e_company_id[0]	= (SUN_EN >> 16) & 0xff;
		eui.e_company_id[1]	= (SUN_EN >> 8) & 0xff;
		eui.e_company_id[2]	= SUN_EN & 0xff;
		eui.e_timestamp[0]	= hibyte(hiword(tval));
		eui.e_timestamp[1]	= lobyte(hiword(tval));
		eui.e_timestamp[2]	= hibyte(loword(tval));
		eui.e_timestamp[3]	= lobyte(loword(tval));
		for (i = 0; i < min(mac_len, sizeof (eui.e_mac)); i++) {
			eui.e_mac[i] = mac_addr[i];
		}

		/*
		 * To prevent duplicate GUIDs we need to sleep for one
		 * second here since part of the GUID is a time stamp with
		 * a one second resolution.
		 */
		(void) sleep(1);
	}

	if (tgt_xml_encode((uint8_t *)&eui, sizeof (eui), guid,
	    &guid_size) == False) {
		return (False);
	} else
		return (True);
}

Boolean_t
util_create_guid_naa(char **guid)
{
	naa_16_t	naa;
	/*
	 * We only have room for 32bits of data in the GUID. The hiword/loword
	 * macros will not work on 64bit variables. The work, but produce
	 * invalid results on Big Endian based machines.
	 */
	uint32_t	tval = (uint_t)time((time_t *)0);
	size_t		guid_size;
	int		i, fd;

	if ((mac_len == 0) && (if_find_mac(NULL) == False)) {

		/*
		 * By default strict GUID generation is enforced. This can
		 * be disabled by using the correct XML tag in the configuration
		 * file.
		 */
		if (enforce_strict_guid == True)
			return (False);

		/*
		 * There's no MAC address available and we've even tried
		 * a second time to get one. So fallback to using a random
		 * number for the MAC address.
		 */
		if ((fd = open("/dev/random", O_RDONLY)) < 0)
			return (False);
		if (read(fd, &naa, sizeof (naa)) != sizeof (naa))
			return (False);
		(void) close(fd);

	} else {
		bzero(&naa, sizeof (naa));

		/*
		 * Set vendor specific identifier and extension.
		 */
		naa.n_timestamp[0]	= hibyte(hiword(tval));
		naa.n_timestamp[1]	= lobyte(hiword(tval));
		naa.n_timestamp[2]	= hibyte(loword(tval));
		naa.n_timestamp[3]	= lobyte(loword(tval));
		for (i = 0; i < min(mac_len, sizeof (naa.n_mac)); i++) {
			naa.n_mac[i] = mac_addr[i];
		}

		/*
		 * To prevent duplicate GUIDs we need to sleep for one
		 * second here since part of the GUID is a time stamp with
		 * a one second resolution.
		 */
		(void) sleep(1);
	}

	/*
	 * Set NAA (6) and IEEE Company_ID.
	 */
	naa.n_naa		= SUN_NAA_16_TYPE;
	naa.n_company_id_hi	= (SUN_EN >> 20) & 0x0f;
	naa.n_company_id_b1	= (SUN_EN >> 12) & 0xff;
	naa.n_company_id_b2	= (SUN_EN >> 4) & 0xff;
	naa.n_company_id_lo	= SUN_EN & 0x0f;
	if (tgt_xml_encode((uint8_t *)&naa, sizeof (naa), guid,
	    &guid_size) == False) {
		return (False);
	} else
		return (True);
}

/*
 * []----
 * | create_geom -- based on size, determine best fit for CHS
 * |
 * | Given size in bytes, which will be adjusted to blocks, find
 * | the best fit for making (C * H * S == blocks)
 * |
 * | Note that the following algorithm was derived from the
 * | common disk label implementation, cmlb_convert_geometry().
 * |
 * []----
 */
void
create_geom(diskaddr_t size, int *cylinders, int *heads, int *spt)
{
	diskaddr_t	blocks = size >> 9;  /* 512 bytes/block */

	/*
	 * For all devices we calculate cylinders using the heads and sectors
	 * we assign based on capacity of the device.  The algorithm is
	 * designed to be compatible with the way other operating systems
	 * lay out fdisk tables for X86 and to insure that the cylinders never
	 * exceed 65535 to prevent problems with X86 ioctls that report
	 * geometry.
	 * For some smaller disk sizes we report geometry that matches those
	 * used by X86 BIOS usage. For larger disks, we use SPT that are
	 * multiples of 63, since other OSes that are not limited to 16-bits
	 * for cylinders stop at 63 SPT we make do by using multiples of 63 SPT.
	 *
	 * The following table (in order) illustrates some end result
	 * calculations:
	 *
	 * Maximum number of blocks	nhead	nsect
	 *
	 * 2097152 (1GB)		 64	 32
	 * 16777216 (8GB)		128	 32
	 * 1052819775 (502.02GB)	255	 63
	 * 2105639550 (0.98TB)		255	126
	 * 3158459325 (1.47TB)		255	189
	 * 4211279100 (1.96TB)		255	252
	 * 5264098875 (2.45TB)		255	315
	 * ...
	 */

	if (blocks <= 0x200000) {
		*heads = 64;
		*spt = 32;
	} else if (blocks <= 0x01000000) {
		*heads = 128;
		*spt = 32;
	} else {
		*heads = 255;

		/* make sectors-per-track be smallest multiple of 63 */
		*spt = ((blocks +
		    (UINT16_MAX * 255 * 63) - 1) /
		    (UINT16_MAX * 255 * 63)) * 63;

		if (*spt == 0)
			*spt = (UINT16_MAX / 63) * 63;
	}

	/* cyls/dsk = (sectors/dsk) / (sectors/trk * tracks/cyl) */
	*cylinders = blocks / (*spt * *heads);
}

/*
 * []----
 * | strtol_multiplier -- common method to deal with human type numbers
 * []----
 */
Boolean_t
strtoll_multiplier(char *str, uint64_t *sp)
{
	char		*m;
	uint64_t	size;

	size = strtoll(str, &m, 0);
	if (m && *m) {
		switch (*m) {
		case 't':
		case 'T':
			size *= 1024;
			/*FALLTHRU*/
		case 'g':
		case 'G':
			size *= 1024;
			/*FALLTHRU*/
		case 'm':
		case 'M':
			size *= 1024;
			/*FALLTHRU*/
		case 'k':
		case 'K':
			size *= 1024;
			break;

		default:
			return (False);
		}
	}

	*sp = size;
	return (True);
}

/*
 * []----
 * | util_title -- print out start/end title in consistent manner
 * []----
 */
void
util_title(target_queue_t *q, int type, int num, char *title)
{
	char	*type_str;
	int	len, pad;

	len	= strlen(title);
	pad	= len & 1;

	switch (type) {
	case Q_CONN_LOGIN:
	case Q_CONN_NONIO:
		type_str	= "CON";
		break;

	case Q_SESS_LOGIN:
	case Q_SESS_NONIO:
		type_str	= "SES";
		break;

	case Q_STE_NONIO:
		type_str	= "SAM";
		break;

	default:
		type_str	= "UGH";
		break;
	}

	queue_prt(q, type, "%s%x  ---- %*s%s%*s ----\n", type_str, num,
	    ((60 - len) / 2), "", title, ((60 - len) / 2) + pad, "");
}

/*
 * []----
 * | task_to_str -- convert task management event to string (DEBUG USE)
 * []----
 */
char *
task_to_str(int func)
{
	switch (func) {
	case ISCSI_TM_FUNC_ABORT_TASK:		return ("Abort");
	case ISCSI_TM_FUNC_ABORT_TASK_SET:	return ("Abort Set");
	case ISCSI_TM_FUNC_CLEAR_ACA:		return ("Clear ACA");
	case ISCSI_TM_FUNC_CLEAR_TASK_SET:	return ("Clear Task");
	case ISCSI_TM_FUNC_LOGICAL_UNIT_RESET:	return ("LUN Reset");
	case ISCSI_TM_FUNC_TARGET_WARM_RESET:	return ("Target Warm Reset");
	case ISCSI_TM_FUNC_TARGET_COLD_RESET:	return ("Target Cold Reset");
	case ISCSI_TM_FUNC_TASK_REASSIGN:	return ("Task Reassign");
	default:				return ("Unknown");
	}
}

/*
 * []----
 * | xml_rtn_msg -- create a common format for XML replies to management UI
 * []----
 */
void
xml_rtn_msg(char **buf, err_code_t code)
{
	char	lbuf[16];

	tgt_buf_add_tag_and_attr(buf, XML_ELEMENT_ERROR, "version='1.0'");
	(void) snprintf(lbuf, sizeof (lbuf), "%d", code);
	tgt_buf_add(buf, XML_ELEMENT_CODE, lbuf);
	tgt_buf_add(buf, XML_ELEMENT_MESSAGE, errcode_to_str(code));
	tgt_buf_add_tag(buf, XML_ELEMENT_ERROR, Tag_End);
}

/*
 * []----
 * | thick_provo_start -- start an initialization thread for targ/lun
 * []----
 */
void *
thick_provo_start(void *v)
{
	thick_provo_t	*tp	= (thick_provo_t *)v;
	msg_t		*m;
	Boolean_t	rval;
	char		*err	= NULL;

	/*
	 * Add this threads information to the main queue. This is
	 * used in case the administrator decides to remove the LU
	 * before the initialization is complete.
	 */
	(void) pthread_mutex_lock(&thick_mutex);
	if (thick_head == NULL) {
		thick_head = tp;
	} else {
		thick_tail->next = tp;
		tp->prev = thick_tail;
	}
	thick_tail = tp;
	(void) pthread_mutex_unlock(&thick_mutex);

	/*
	 * This let's the parent thread know this thread is running.
	 */
	queue_message_set(tp->q, 0, msg_mgmt_rply, 0);

	/* ---- Start the initialization of the LU ---- */
	rval = t10_thick_provision(tp->targ_name, tp->lun, tp->q);

	/* ---- Remove from the linked list ---- */
	(void) pthread_mutex_lock(&thick_mutex);
	if (tp->prev == NULL) {
		assert(tp == thick_head);
		thick_head = tp->next;
		if (tp->next == NULL) {
			assert(tp == thick_tail);
			thick_tail = NULL;
		} else
			tp->next->prev = NULL;
	} else {
		tp->prev->next = tp->next;
		if (tp->next != NULL)
			tp->next->prev = tp->prev;
		else
			thick_tail = tp->prev;
	}
	(void) pthread_mutex_unlock(&thick_mutex);

	/*
	 * There's a race condition where t10_thick_provision() could
	 * finish and before the thick_mutex lock is grabbed again
	 * that another thread running the thick_provo_stop() could
	 * find a match and send a shutdown message. If that happened
	 * that thread would wait forever in queue_message_get(). So,
	 * After this target/lun pair has been removed check the message
	 * queue one last time to see if there's a message available.
	 * If so, send an ack.
	 */
	m = queue_message_try_get(tp->q);
	if (m != NULL) {
		assert(m->msg_type == msg_shutdown);
		queue_message_set((target_queue_t *)m->msg_data, 0,
		    msg_shutdown_rsp, 0);
	}

	if (rval == True)
		iscsi_inventory_change(tp->targ_name);
	else {
		queue_prt(mgmtq, Q_GEN_ERRS, "Failed to initialize %s/%d\n",
		    tp->targ_name, tp->lun);
		syslog(LOG_ERR, "Failed to initialize %s, LU%d", tp->targ_name,
		    tp->lun);
		remove_target_common(tp->targ_name, tp->lun, &err);
		if (err != NULL) {

			/*
			 * There's not much we can do here. The most likely
			 * cause of not being able to remove the target is
			 * that it's LU 0 and there is currently another
			 * LU allocated.
			 */
			queue_prt(mgmtq, Q_GEN_ERRS,
			    "Failed to remove target\n");
			syslog(LOG_ERR, "Failed to remove target/lun after "
			    "initialization failure");
		}
	}

	free(tp->targ_name);
	queue_free(tp->q, NULL);
	free(tp);

	queue_message_set(mgmtq, 0, msg_pthread_join,
	    (void *)(uintptr_t)pthread_self());
	return (NULL);
}

/*
 * []----
 * | thick_provo_stop -- stop initialization thread for given targ/lun
 * []----
 */
void
thick_provo_stop(char *targ, int lun)
{
	thick_provo_t	*tp;
	target_queue_t	*q	= queue_alloc();

	(void) pthread_mutex_lock(&thick_mutex);
	tp = thick_head;
	while (tp) {
		if ((strcmp(tp->targ_name, targ) == 0) && (tp->lun == lun)) {
			queue_message_set(tp->q, 0, msg_shutdown, (void *)q);
			/*
			 * Drop the global mutex because it's entirely
			 * possible for a thick_provo_start thread to be
			 * in the early stages in which it will can call
			 * thick_provo_chk() from the T10 SAM code.
			 */
			(void) pthread_mutex_unlock(&thick_mutex);

			queue_message_free(queue_message_get(q));

			/*
			 * Pick the lock back up since it'll make the
			 * finish stage easier to deal with.
			 */
			(void) pthread_mutex_lock(&thick_mutex);
			break;
		}
		tp = tp->next;
	}
	(void) pthread_mutex_unlock(&thick_mutex);
	queue_free(q, NULL);
}

/*
 * []----
 * | thick_provo_chk_thr -- see if there's an initialization thread running
 * []----
 */
Boolean_t
thick_provo_chk_thr(char *targ, int lun)
{
	thick_provo_t	*tp;
	Boolean_t	rval = False;

	(void) pthread_mutex_lock(&thick_mutex);
	tp = thick_head;
	while (tp) {
		if ((strcmp(tp->targ_name, targ) == 0) && (tp->lun == lun)) {
			rval = True;
			break;
		}
		tp = tp->next;
	}
	(void) pthread_mutex_unlock(&thick_mutex);

	return (rval);
}

/*
 * []----
 * | remove_target_common -- remove targ/lun from system.
 * |
 * | This is a common function that's used both by the normal remove
 * | target code and when a write failure occurs during initialization.
 * | It will handle being given either the local target name or the full
 * | IQN name of the target.
 * []----
 */
void
remove_target_common(char *name, int lun_num, char **msg)
{
	tgt_node_t	*targ			= NULL;
	tgt_node_t	*list, *lun, *c;
	char		path[MAXPATHLEN];
	char		*tname			= NULL;
	char		*iname			= NULL;
	int		chk;

	while ((targ = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		/* ---- Look for a match on the friendly name ---- */
		if (strcmp(targ->x_value, name) == 0) {
			tname = name;
			break;
		}

		/* ---- Check to see if they gave the IQN name instead ---- */
		if ((tgt_find_value_str(targ, XML_ELEMENT_INAME, &iname) ==
		    True) && (strcmp(iname, name) == 0))
			break;
		else {
			free(iname);
			iname = NULL;
		}
	}

	/* ---- Check to see if it's already been removed ---- */
	if (targ == NULL) {
		return;
	}

	/*
	 * We need both the friendly and IQN names so figure out which wasn't
	 * given and find it's value.
	 */
	if (tname == NULL)
		tname = targ->x_value;
	if (iname == NULL) {
		if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &iname) ==
		    False) {
			xml_rtn_msg(msg, ERR_INTERNAL_ERROR);
			return;
		}
	}

	if ((list = tgt_node_next(targ, XML_ELEMENT_LUNLIST, NULL)) == NULL)
		goto error;

	if (lun_num == 0) {

		/*
		 * LUN must be the last one removed, so check to
		 * see if others are still present.
		 */
		lun = NULL;
		while ((lun = tgt_node_next(list, XML_ELEMENT_LUN, lun)) !=
		    NULL) {
			if (tgt_find_value_int(lun, XML_ELEMENT_LUN, &chk) ==
			    False)
				goto error;

			if (chk != lun_num) {
				xml_rtn_msg(msg, ERR_LUN_ZERO_NOT_LAST);
				goto error;
			}
		}
	} else {

		/*
		 * Make sure the LU exists that's being removed
		 */
		lun = NULL;
		while ((lun = tgt_node_next(list, XML_ELEMENT_LUN, lun)) !=
		    NULL) {
			if (tgt_find_value_int(lun, XML_ELEMENT_LUN, &chk) ==
			    False)
				goto error;

			if (chk == lun_num) {
				lun = tgt_node_alloc(XML_ELEMENT_LUN, Int,
				    &lun_num);
				(void) tgt_node_remove(list, lun, MatchBoth);
				tgt_node_free(lun);
				break;
			}
		}
		if (lun == NULL) {
			xml_rtn_msg(msg, ERR_LUN_NOT_FOUND);
			goto error;
		}
	}

	/* ---- Say goodbye to that data ---- */
	(void) snprintf(path, sizeof (path), "%s/%s/%s%d", target_basedir,
	    iname, LUNBASE, lun_num);
	(void) unlink(path);
	(void) snprintf(path, sizeof (path), "%s/%s/%s%d", target_basedir,
	    iname, PARAMBASE, lun_num);
	(void) unlink(path);

	(void) mgmt_param_remove(tname, lun_num);

	/*
	 * If the was LUN 0 then do to the previous check
	 * we know that no other files exist in the target
	 * directory so the target information can be removed
	 * along with the directory.
	 */
	if (lun_num == 0) {
		(void) snprintf(path, sizeof (path), "%s/%s", target_basedir,
		    iname);
		(void) rmdir(path);

		/*
		 * Don't forget to remove the symlink to
		 * the target directory.
		 */
		(void) snprintf(path, sizeof (path), "%s/%s", target_basedir,
		    tname);
		(void) unlink(path);

		/*
		 * 'tname' is just a reference to the memory within
		 * the targets_config structure. So once the tgt_node_remove()
		 * is called 'tname' is no longer valid.
		 */
		c = tgt_node_alloc(XML_ELEMENT_TARG, String, tname);
		(void) tgt_node_remove(targets_config, c, MatchBoth);
		tgt_node_free(c);
	}

	/*
	 * Not much we can do here if we fail to updated the config.
	 */
	if (mgmt_config_save2scf() == False)
		syslog(LOG_ERR, "Failed to update target configuration!");

error:
	if (iname != NULL)
		free(iname);
}

/*
 * []----
 * | validate_xml
 * |
 * | This function checks if there is predefined entities &<>'" in xml request
 * []----
 */
Boolean_t
validate_xml(char *req)
{
	in_mark_t in_mark = in_none;

	if (req == NULL)
		return (False);
	for (; *req != '\0'; req++) {
		if (in_mark == in_none) {
			if (*req == '<') {
				in_mark = in_lt;
				continue;
			} else if (*req == '&') {
				in_mark = in_amp;
				continue;
			} else if (strchr("\"\'>", *req) != NULL) {
				return (False);
			}
		} else if (in_mark == in_lt) {
			if (*req == '>') {
				in_mark = in_none;
				continue;
			} else if (*req == '<') {
				return (False);
			}
		} else {
			if (*req == ';') {
				in_mark = in_none;
				continue;
			} else if (*req == '&' || *req == '<') {
				return (False);
			}
		}
	}

	if (in_mark == in_none)
		return (True);
	else
		return (False);
}

/*
 * []----
 * | get_local_name
 * |
 * | This function fetches local name from a iscsi-name
 * | Caller is responsible to free the string.
 * []----
 */
char *
get_local_name(char *iname)
{
	tgt_node_t	*targ = NULL;
	char		*str;
	char		*ret = NULL;

	while ((targ = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &str) == True) {
			if (strcmp(str, iname) == 0)
				ret = strdup(targ->x_value);
			free(str);
			if (ret != NULL)
				break;
		}
	}
	return (ret);
}
