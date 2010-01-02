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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <iscsitgt_impl.h>

#include "isns_protocol.h"
#include "isns_client.h"
#include "target.h"
#include "queue.h"


typedef struct {
	uint32_t	pf_family;
	uint32_t	ip_len;
	uint32_t	ai_addrlen;
	union {
		in_addr_t	in;
		in6_addr_t	in6;
	} ip_adr;
} ip_t;

#define	ISNS_TGT_LOGOUT		54321

extern target_queue_t	*mgmtq;

/*
 * Global
 * Parameters for ESI/SCN processing.
 * scn_port: ESI/SCN port to receive ISNS_ESI & ISNS_SCN messages
 * isns_args:
 * eid_ip: Entity IP info
 */
static	int scn_port = 0;
static	esi_scn_arg_t	isns_args = {{0}, {0}, 0};
static	ip_t	eid_ip;
static	int	num_reg = 0;
static	pthread_t	scn_tid = 0;
static	pthread_t	isns_tid = 0;
static	Boolean_t	isns_shutdown = True;
static	Boolean_t	connection_thr_bail_out = False;
static int ISNS_SLEEP_SECS = 20;
Boolean_t	isns_server_connection_thr_running = False;
target_queue_t	*mgmtq = NULL;

static	int	get_ip_addr(char *node, ip_t *sa);
static	int	isns_op_all(uint16_t);
static	int	append_tpgt(tgt_node_t *, isns_pdu_t *);
static	void	process_esi(int, isns_pdu_t *);
static	void	process_scn(int, isns_pdu_t *);
static	void	*esi_scn_thr(void *);
static	int	process_rsp(isns_pdu_t *, isns_rsp_t *);
static	int	isns_dev_attr_reg(int, tgt_node_t *, char *, char *);
static	int	isns_dev_attr_dereg(int, char *);
static	int	isns_scn_reg(int, char *);
static	int	isns_scn_dereg(int so, char *node);
static	tgt_node_t	*find_tgt_by_name(char *, char **);
static	tgt_node_t	*find_next_tgt(tgt_node_t *, char **);
static int isns_populate_and_update_server_info(Boolean_t state);
static int get_addr_family(char *node);

/*
 * find_tgt_by_name searches DB by iscsi name or local name, if found
 * returns tgt_node_t.  iname needs to be free by caller.
 */
static tgt_node_t *
find_tgt_by_name(char *targ, char **iname)
{
	tgt_node_t	*tgt = NULL;

	while ((tgt = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    tgt)) != NULL) {
		if (tgt_find_value_str(tgt, XML_ELEMENT_INAME, iname)
		    == FALSE) {
			syslog(LOG_ALERT, "ISNS: Missing iscsi name\n");
			break;
		}
		/* match either iscsi name or local name */
		if (strcmp(targ, tgt->x_value) == 0 ||
		    strcmp(targ, *iname) == 0) {
			return (tgt);
		}
		free(*iname);
	}
	return (NULL);
}

static tgt_node_t *
find_next_tgt(tgt_node_t *tgt, char **iname)
{
	while ((tgt = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    tgt)) != NULL) {
		if (tgt_find_value_str(tgt, XML_ELEMENT_INAME, iname)
		    == FALSE) {
			continue;
		}
		return (tgt);
	}
	return (NULL);
}

/*
 * Find ip-addr associated with TPGT, don't send if no ip-addr is
 * found for a TPGT
 */
static int
append_tpgt(tgt_node_t *tgt, isns_pdu_t *cmd)
{
	tgt_node_t	*t, *x;
	tgt_node_t	*pgt	= NULL;
	tgt_node_t	*iplist	= NULL;
	tgt_node_t	*tpgt	= NULL;
	ip_t		eid;

	/* Always add the default TPGT (1) */
	(void) isns_append_attr(cmd, ISNS_PG_TAG_ATTR_ID, ISNS_PG_TAG_SZ, NULL,
	    1);
	if (isns_append_attr(cmd, ISNS_PG_PORTAL_IP_ADDR_ATTR_ID,
	    eid_ip.ai_addrlen, (void *)&eid_ip.ip_adr,
	    eid_ip.ip_len) != 0) {
		return (-1);
	}
	if (isns_append_attr(cmd, ISNS_PG_PORTAL_PORT_ATTR_ID,
	    ISNS_PORT_SZ, NULL, iscsi_port) != 0) {
		return (-1);
	}

	/* Get the remainning TPGT-LIST */
	if ((t = tgt_node_next(tgt, XML_ELEMENT_TPGTLIST, NULL))
	    != NULL) {
		/* find tgpt from tpgt-list */
		while ((pgt = tgt_node_next(t, XML_ELEMENT_TPGT, pgt))
		    != NULL) {
			/* update isns only if TPGT contains ip_addr */
			while ((tpgt = tgt_node_next_child(main_config,
			    XML_ELEMENT_TPGT, tpgt)) != NULL) {
				if (strcmp(pgt->x_value, tpgt->x_value) != 0)
					continue;
				if ((iplist = tgt_node_next(tpgt,
				    XML_ELEMENT_IPADDRLIST, NULL)) != NULL)
					break;
			}
			if (tpgt == NULL || iplist == NULL)
				continue;
			if (isns_append_attr(cmd, ISNS_PG_TAG_ATTR_ID,
			    ISNS_PG_TAG_SZ, NULL,
			    strtol(pgt->x_value, NULL, 0)) != 0) {
				return (-1);
			}

			/* get ip-addr & port */
			for (x = iplist->x_child; x; x = x->x_sibling) {
				if (get_ip_addr(x->x_value, &eid) < 0)
					continue;
				if (isns_append_attr(cmd,
				    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID,
				    eid.ai_addrlen, (void *)&eid.ip_adr,
				    eid.ip_len) != 0) {
					return (-1);
				}
				if (isns_append_attr(cmd,
				    ISNS_PG_PORTAL_PORT_ATTR_ID,
				    ISNS_PORT_SZ, NULL, iscsi_port) != 0) {
					return (-1);
				}
			}
		}
	}

	return (0);
}

/*
 * process_scn()
 *	-Added/Updated object: nop, initiator is verified during connect
 *
 *	-Removed object: logout_targ if still connected
 *
 * RFC 4171 section 5.6.5.9
 * destination attribute is always the 1st attribute in the SCN message,
 * then follows by SCN_BITMAP(35) & Source_Attribute(32)
 */
static void
process_scn(int so, isns_pdu_t *scn)
{
	uint8_t		*ptr = scn->payload;
	isns_tlv_t	*tlv;
	uint16_t	cnt = 0;
	uint32_t	got_dest = 0;
	uint32_t	got_source = 0;
	uint32_t	bitmap = 0;
	uint32_t	got_bitmap = 0;
	char		dest[MAXNAMELEN];
	char		source[MAXNAMELEN];

	queue_prt(mgmtq, Q_ISNS_DBG, "PROCESS_SCN %u\n",
	    scn->payload_len);

	if (scn->payload_len < TAG_LEN_SZ) {
		syslog(LOG_ALERT, "ISNS SCN message error\n");
		return;
	}

	while (cnt < scn->payload_len) {
		/* LINTED */
		tlv = (isns_tlv_t *)ptr;
		tlv->attr_id = ntohl(tlv->attr_id);
		tlv->attr_len = ntohl(tlv->attr_len);
		queue_prt(mgmtq, Q_ISNS_DBG, "PROCESS_SCN %u %u\n",
		    tlv->attr_id, tlv->attr_len);
		/*
		 * devAttrQry the source attribute, process if node_type
		 * is initiator
		 */
		switch (tlv->attr_id) {
			case ISNS_ISCSI_NAME_ATTR_ID:
				if (got_dest == 0) {
					bcopy(tlv->attr_value, dest,
					    tlv->attr_len);
					queue_prt(mgmtq, Q_ISNS_DBG,
					    "PROCESS_SCN dest %s\n", dest);
					got_dest = 1;
				} else {
					bcopy(tlv->attr_value, source,
					    tlv->attr_len);
					queue_prt(mgmtq, Q_ISNS_DBG,
					    "PROCESS_SCN source %s\n", source);
					got_source = 1;
				}
				break;
			case ISNS_ISCSI_SCN_BITMAP_ATTR_ID:
				bcopy(tlv->attr_value, &bitmap, tlv->attr_len);
				bitmap = ntohl(bitmap);
				queue_prt(mgmtq, Q_ISNS_DBG,
				    "PROCESS_SCN bitmap %u\n", bitmap);
				got_bitmap = 1;
				break;
			default:
				queue_prt(mgmtq, Q_ISNS_DBG,
				    "PROCESS_SCN DEFAULT\n");
				break;
		}

		if (got_source && !got_bitmap) {
			queue_prt(mgmtq, Q_ISNS_DBG,
			    "process_scn: message out-of-order\n");
			return;
		}

		if (got_source && got_bitmap) {
			switch (bitmap) {
				case ISNS_OBJ_ADDED:
				case ISNS_OBJ_UPDATED:
					queue_prt(mgmtq, Q_ISNS_DBG,
					    "PROCESS_SCN OBJ ADDED");
					(void) isns_update();
					break;
				case ISNS_OBJ_REMOVED:
					queue_prt(mgmtq, Q_ISNS_DBG,
					    "PROCESS_SCN OBJ REMOVED");
					/* logout target */
					if (got_dest == 0) {
						syslog(LOG_ALERT,
						    "ISNS protocol error\n");
						continue;
					}
					logout_targ(dest);
					break;
				default:
					break;
			}

			/* clear got_xxx */
			got_source = 0;
			got_bitmap = 1;
		}

		/* next attribute */
		cnt += ISNS_ATTR_SZ(tlv->attr_len);
		ptr += ISNS_ATTR_SZ(tlv->attr_len);
	}
	queue_prt(mgmtq, Q_ISNS_DBG, "DONE PROCESS_SCN\n");
}

/*
 * Process ESI requires a success response only
 */
static void
process_esi(int so, isns_pdu_t *esi)
{
	isns_rsp_t	*cmd;
	int		pl_len;

	if (isns_create_pdu(ISNS_ESI_RSP, 0, (isns_pdu_t **)&cmd) != 0) {
		return;
	}

	pl_len = esi->payload_len + ISNS_STATUS_SZ;
	if (pl_len > MAX_PDU_PAYLOAD_SZ) {
		syslog(LOG_ALERT, "process_esi: payload size exceeded");
		isns_free_pdu(cmd);
		return;
	}

	/* change the xid to the request xid */
	cmd->xid = htons(esi->xid);
	cmd->status = htonl(ISNS_RSP_SUCCESSFUL);

	/* copy original data */
	bcopy(esi->payload, cmd->data, esi->payload_len);
	cmd->pdu_len = htons(pl_len);

	if (isns_send(so, (isns_pdu_t *)cmd) < 0) {
		syslog(LOG_ALERT, "process_esi failed to isns_send");
	}

	isns_free_pdu(cmd);
}

static int
is_isns_server_up(char *server) {
	int			so;
	socklen_t		len;
	struct sockaddr		sa;

	/* no server specified */
	if (server == NULL) {
		return (-1);
	}
	/*
	 * open isns server connect and determine which PF_INET to use
	 */
	if ((so = isns_open(server)) < 0) {
		syslog(LOG_ERR,
		    "isns server %s not found",
			server);
		return (-1);
	}
	len = sizeof (sa);
	if (getsockname(so, &sa, &len) < 0) {
		isns_close(so);
		syslog(LOG_ALERT,
			"isns getsockname failed");
		return (-1);
	}
	isns_close(so);

	if (sa.sa_family != PF_INET &&
		sa.sa_family != PF_INET6) {
		syslog(LOG_ERR,
			"isns unknown domain type");
		return (-1);
	}
	return (0);
}

/*
 * This thread sit's in a loop and ensures that it keeps checking for
 * connection to isns_server. Once the connection works it registers
 * with the isns and bails out.
 * We expect the isns server to be fault taulerant and has persistence
 * for the registered entries.
 */
static void *
isns_server_connection_thr(void *arg)
{
	Boolean_t registered_targets = False;
	char server[MAXHOSTNAMELEN + 1] = {0};

	while (isns_shutdown == False &&
	    connection_thr_bail_out == False) {
		/* current server */
		(void) strcpy(server, isns_args.server);

		if (is_isns_server_up(server) == 0) {
			if (registered_targets == False) {
				/*
				 * register all targets, what happens if
				 * no targets are created yet? this should
				 * not be a failure, when new target gets
				 * created, update gets call. what if SCN
				 * register fails?
				 */
				if (isns_reg_all() == 0) {
					/* scn register all targets */
					if (isns_op_all(ISNS_SCN_REG) != 0) {
						syslog(LOG_ERR,
						    "SCN registrations"
						    " failed\n");
						(void) isns_op_all(
						    ISNS_DEV_DEREG);
						registered_targets = False;
					} else {
						registered_targets = True;
						break;
					}
				}
			}
		} else {
			syslog(LOG_INFO,
			    "isns server %s is not reachable",
			    server);
			registered_targets = False;
		}
		(void) sleep(ISNS_SLEEP_SECS);
		/* If isns was disabled, deregister and close the thread */
		if (isns_enabled() == False) {
			syslog(LOG_INFO,
			    "isns server is disabled, dergister target");
			isns_fini();
			break;
		}

	}
	queue_message_set(mgmtq, 0, msg_pthread_join,
	    (void *)(uintptr_t)pthread_self());

	return (NULL);
}

/*
 * esi_scn_thr() is the thread creates an end point to receive and process
 * ESI & SCN messages.  This thread is created when isns_access is enabled
 * and for the duration of the iscsi daemon
 */
static void *
esi_scn_thr(void *arg)
{
	struct sockaddr		sa, *ai;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
	int			so, fd, pf;
	socklen_t		len;
	char			strport[NI_MAXSERV];
	isns_pdu_t		*scn = NULL;
	struct timeval timeout;
	fd_set fdset;
	int socket_ready = 0;

	pf = get_addr_family(isns_args.entity);
	if (pf == PF_INET) {
		bzero(&sin, sizeof (sin));
		sin.sin_family = PF_INET;
		sin.sin_port = htons(0);
		sin.sin_addr.s_addr = INADDR_ANY;
		ai = (struct sockaddr *)&sin;
		len = sizeof (sin);
	} else if (pf == PF_INET6) {
		bzero(&sin6, sizeof (sin6));
		sin6.sin6_family = PF_INET6;
		sin6.sin6_port = htons(0);
		sin6.sin6_addr = in6addr_any;
		ai = (struct sockaddr *)&sin6;
		len = sizeof (sin6);
	} else {
		syslog(LOG_ERR, "Bad address family. Exit esi_scn_thr");
		return (NULL);
	}

	/*
	 * create and bind SCN socket
	 * save the scn port info
	 */
	if ((so = socket(pf, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ALERT, "create isns socket failed");
		return (NULL);
	}

	(void) setsockopt(so, SOL_SOCKET, SO_REUSEADDR, 0, 0);

	if (bind(so, ai, len) < 0) {
		syslog(LOG_ALERT, "esi_scn_thr: bind failed");
		(void) close(so);
		return (NULL);
	}

	/* get scn port info */
	len = sizeof (sa);
	if (getsockname(so, &sa, &len) < 0) {
		syslog(LOG_ALERT, "isns getsockname failed");
		(void) close(so);
		return (NULL);
	}
	if (getnameinfo(&sa, len, NULL, 0, strport, NI_MAXSERV,
	    NI_NUMERICSERV) != 0) {
		syslog(LOG_ALERT, "isns getnameinfo failed");
		(void) close(so);
		return (NULL);
	}
	scn_port = atoi(strport);


	if (listen(so, 5) < 0) {
		syslog(LOG_ALERT, "esi_scn_thr: failed listen");
		(void) close(so);
		return (NULL);
	}

	/* listen for esi or scn messages */
	while (isns_shutdown == False) {
		/* ISNS_ESI_INTERVAL_ATTR_ID is set to 10s */
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		FD_ZERO(&fdset);
		FD_SET(so, &fdset);

		socket_ready = select(so + 1, &fdset, NULL, NULL, &timeout);

		/* If disabled bail out, dont care about packets */
		if (isns_enabled() == False) {
			syslog(LOG_INFO,
			    "isns server is disabled, dergister target");
			isns_fini();
			(void) close(so);
			return (NULL);
		}

		if (socket_ready < 0) {
			syslog(LOG_ERR,
			    "esi_scn_thr: select failed, retrying.");
			continue;
		} else if (socket_ready == 0) { /* timeout */
			continue;
		} else {
			/* Socket is ready */
			if ((fd = accept(so, &sa, &len)) < 0) {
				syslog(LOG_ALERT, "esi_scn_thr: failed accept");
				continue;
			}
		}
		if (isns_recv(fd, (isns_rsp_t **)&scn) == 0) {
			/* Just return success for ESI */
			switch (scn->func_id) {
				case ISNS_ESI:
					process_esi(fd, scn);
					break;
				case ISNS_SCN:
					/* call the SCN process function */
					process_scn(fd, scn);
					break;
				default:
					syslog(LOG_ERR,
					    "esi_scn_thr: Invalid funcid %d\n",
					    scn->func_id);
					break;
			}
			/* free response resource */
			isns_free_pdu(scn);
		} else {
			syslog(LOG_ALERT, "esi_scn_thr fails isns_recv ");
		}

		(void) close(fd);
	}
	(void) close(so);
	return (NULL);
}

/*
 * Perform operation on all targets
 */
static int
isns_op_all(uint16_t op)
{
	int		so;
	tgt_node_t	*tgt = NULL;
	char		*iname;

	if (isns_server_connection_thr_running == False) {
		syslog(LOG_ERR,
		    "isns_op_all: iSNS discovery is not running."
		    " Check the previous iSNS initialization error.");
		return (-1);
	}

	if ((so = isns_open(isns_args.server)) == -1) {
		syslog(LOG_ERR, "isns_op_all: failed to open isns server %s",
		    isns_args.server);
		return (-1);
	}

	while ((tgt = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    tgt)) != NULL) {
		if (tgt_find_value_str(tgt, XML_ELEMENT_INAME, &iname)
		    == FALSE) {
			continue;
		}

		switch (op) {
			case ISNS_DEV_DEREG:
				if (isns_dev_attr_dereg(so, iname) == -1) {
					syslog(LOG_ERR,
					    "ISNS de-register failed\n");
				}
				num_reg = 0;
				break;
			case ISNS_SCN_DEREG:
				if (isns_scn_dereg(so, iname) == -1) {
					syslog(LOG_ERR,
					    "ISNS SCN de-register failed\n");
				}
				break;
			case ISNS_SCN_REG:
				if (isns_scn_reg(so, iname) == -1) {
					syslog(LOG_ERR,
					    "ISNS SCN register failed\n");
				}
				break;
			case ISNS_TGT_LOGOUT:
				logout_targ(iname);
				break;
			default:
				break;
		}

		free(iname);
	}
	isns_close(so);
	return (0);
}

static int
isns_populate_and_update_server_info(Boolean_t update) {
	char		*isns_srv, *isns_port;
	int retcode = 0;

	/* get isns server info */
	(void) tgt_find_value_str(main_config, XML_ELEMENT_ISNS_SERV,
	    &isns_srv);
	if (isns_srv == NULL) {
		syslog(LOG_INFO,
		    "The server has not been setup, "
		    "but enabling the isns access");
		retcode = -1;
		return (retcode);
	}
	isns_port = strchr(isns_srv, ':');
	if (isns_port == NULL) {
		isns_args.isns_port = ISNS_DEFAULT_SERVER_PORT;
	} else {
		isns_args.isns_port = strtoul(isns_port + 1, NULL, 0);
		if (isns_args.isns_port == 0) {
			isns_args.isns_port = ISNS_DEFAULT_SERVER_PORT;
		}
		*isns_port = '\0';
	}

	if (update == True) {
		/* isns_server changed */
		if (strcmp(isns_srv, isns_args.server) != 0) {
			/* de-reg from old iSNS server if it is setup */
			syslog(LOG_INFO,
			    "Detected a new isns server, deregistering"
			    " %s", isns_args.server);
			(void) isns_dereg_all();
			(void) strcpy(isns_args.server, isns_srv);
			/* Register with the new server */
			if (isns_reg_all() == 0) {
				/* scn register all targets */
				if (isns_op_all(ISNS_SCN_REG) != 0) {
					syslog(LOG_ERR,
					    "SCN registrations failed\n");
					(void) isns_op_all(ISNS_DEV_DEREG);
					retcode = -1;
				}
			}
		}
	} else {
		(void) strcpy(isns_args.server, isns_srv);
	}
	free(isns_srv);
	return (retcode);
}

/*
 * isns_init() needs to be call before all ISNS operations.
 * Save the isns_server & entity name.
 * Start esi_scn_thr to receive ESI & SCN messages
 */
int
isns_init(target_queue_t *q)
{
	if (q != NULL)
		mgmtq = q;

	if (isns_enabled() == False)
		return (0);

	/* get local hostname for entity usage */
	if ((gethostname(isns_args.entity, MAXHOSTNAMELEN) < 0) ||
	    (get_ip_addr(isns_args.entity, &eid_ip) < 0)) {
		syslog(LOG_ERR, "isns_init: failed to get host name or host ip"
		    " address for ENTITY properties");
		return (-1);
	}

	isns_shutdown = False;

	(void) isns_populate_and_update_server_info(False);
	if (pthread_create(&scn_tid, NULL,
	    esi_scn_thr, (void *)&isns_args) !=
	    0) {
		syslog(LOG_ALERT, "isns_init failed to pthread_create");
		(void) pthread_kill(isns_tid, SIGKILL);
		return (-1);
	}

	if (pthread_create(&isns_tid, NULL, isns_server_connection_thr,
	    (void *)NULL) != 0) {
		syslog(LOG_ALERT,
		    "isns_init failed to create the "
		    "isns connection thr");
		return (-1);
	}

	isns_server_connection_thr_running = True;
	return (0);
}

/*
 * isns_update gets call on modify_admin, this is changes to
 * isns access and/or isns server
 */
int
isns_update()
{
	Boolean_t is_isns_enabled = isns_enabled();
	/*
	 * If the isns thread was not started before and we are going
	 * enabled from disabled start the threads.
	 */
	if (isns_server_connection_thr_running == False) {
		if (is_isns_enabled == True) {
			if (isns_init(NULL) != 0) {
				return (-1);
			} else {
				return (0);
			}
		} else {
			syslog(LOG_INFO,
			    "isns_update: isns is disabled");
		}
	} else {
		/*
		 * isns is disabled after enabled,
		 * log off all targets and fini isns service
		 */
		if (is_isns_enabled == False) {
			isns_shutdown = True;
			/* pthread_join for the isns thread */
			(void) pthread_join(isns_tid, NULL);
			(void) pthread_join(scn_tid, NULL);
			isns_server_connection_thr_running = False;
		} else {
			/*
			 * Incase the original thread is still running
			 * we should reap it
			 */
			connection_thr_bail_out = True;
			(void) pthread_join(isns_tid, NULL);
			connection_thr_bail_out = False;

			/*
			 * Read the configuration file incase the server
			 * has changed.
			 */
			if (isns_populate_and_update_server_info(True) == -1) {
				return (-1);
			}
		}
	}
	return (0);
}

/*
 * isns_fini is called when isns access is disabled
 */
void
isns_fini()
{
	/*
	 * de-register all targets 1st, this prevents initiator from
	 * logging back in
	 */
	(void) isns_op_all(ISNS_SCN_DEREG);
	(void) isns_op_all(ISNS_DEV_DEREG);

	/* log off all targets */
	(void) isns_op_all(ISNS_TGT_LOGOUT);
}

static int
get_addr_family(char *node) {
	struct addrinfo		*ai = NULL;
	int ret;

	if ((ret = getaddrinfo(node, NULL, NULL, &ai)) != 0) {
		syslog(LOG_ALERT, "get_addr_family: server %s not found : %s",
		    node, gai_strerror(ret));
		return (-1);
	}
	ret = ai->ai_family;
	freeaddrinfo(ai);
	return (ret);
}

static int
get_ip_addr(char *node, ip_t *sa)
{
	struct addrinfo		*ai = NULL, *aip;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	int	ret;

	if ((ret = getaddrinfo(node, NULL, NULL, &ai)) != 0) {
		syslog(LOG_ALERT, "get_ip_addr: %s not found : %s",
		    node, gai_strerror(ret));
		return (-1);
	}

	bzero(sa, sizeof (ip_t));
	aip = ai;
	do {
		sa->ai_addrlen = aip->ai_addrlen;
		sa->pf_family = aip->ai_family;
		switch (aip->ai_family) {
			case PF_INET:
				/* LINTED */
				sin = (struct sockaddr_in *)aip->ai_addr;
				sa->ip_len = sizeof (in_addr_t);
				bcopy(&sin->sin_addr, (void *)&sa->ip_adr.in,
				    sa->ip_len);
				freeaddrinfo(ai);
				return (0);
			case PF_INET6:
				/* LINTED */
				sin6 = (struct sockaddr_in6 *)aip->ai_addr;
				sa->ip_len = sizeof (in6_addr_t);
				bcopy(&sin6->sin6_addr, &sa->ip_adr.in6,
				    sa->ip_len);
				freeaddrinfo(ai);
				return (0);
			default:
				continue;
		}
	} while ((aip = aip->ai_next) != NULL);

	freeaddrinfo(ai);
	return (-1);
}

/*
 * Process isns response, need to verify same transaction id, func_id
 * as the isns command, the isns command is in network byte order,
 * the isns response is in host byte order
 */
static int
process_rsp(isns_pdu_t *cmd, isns_rsp_t *rsp)
{
	queue_prt(mgmtq, Q_ISNS_DBG, "PROCESS_RSP");
	/*
	 * Process responses:
	 *	-verify sucessful response
	 *	-verify match xid
	 *	-process operating attributes
	 * For DevAttrReg & DevAttrQry and most isns command,
	 * the response func_id is  command_func_id | 0x8000.
	 */
	rsp->status = ntohl(rsp->status);
	if (rsp->status != ISNS_RSP_SUCCESSFUL ||
	    rsp->xid != ntohs(cmd->xid) ||
	    rsp->func_id != (ntohs(cmd->func_id) | 0x8000)) {
		queue_prt(mgmtq, Q_ISNS_DBG,
		    "cmd failed with: status= %d xid= %d %d "\
		    "response attribute %x\n", rsp->status, rsp->xid,\
		    ntohs(cmd->xid), rsp->func_id);
		return (-1);
	}

	return (0);
}

/*
 * DevAttrDereg
 */
static int
isns_dev_attr_dereg(int so, char *node)
{
	isns_pdu_t	*cmd = NULL;
	isns_rsp_t	*rsp = NULL;
	uint32_t	flags = 0;
	int		ret = -1;

	queue_prt(mgmtq, Q_ISNS_DBG, "ISNS_DEV_ATTR_DEREG");

	if (isns_create_pdu(ISNS_DEV_DEREG, flags, &cmd) != 0) {
		return (-1);
	}

	/* add source attribute */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(node), node, 0) != 0) {
		goto error;
	}

	/* add delimiter */
	if (isns_append_attr(cmd, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0) != 0) {
		goto error;
	}

	/* add operation attributes */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(node), node, 0) != 0) {
		goto error;
	}

	/* send pdu */
	if (isns_send(so, cmd) == -1) {
		syslog(LOG_ERR, "isns_dev_attr_dereg fails isns_send");
		goto error;
	}

	/* get isns response */
	if (isns_recv(so, &rsp) == -1) {
		syslog(LOG_ERR, "isns_dev_attr_dereg fails isns_recv ");
		goto error;
	}

	/* process response */
	if (process_rsp(cmd, rsp) == 0) {
		/*
		 * Keep the num_reg to a non-negative number.
		 * num_reg is used to keep track of whether there was
		 * any registration occurred or not. Deregstration should
		 * be followed by registration but in case dereg occurs
		 * and somehow it is succeeded keeping num_reg to 0 prevent
		 * any negative effect on subsequent registration.
		 */
		if (num_reg > 0) num_reg--;
		ret = 0;
	}

error:
	/* Free all resouces here */
	if (cmd)
		isns_free_pdu(cmd);
	if (rsp)
		isns_free_pdu(rsp);
	return (ret);
}

/*
 * Register a new node, need to find another node that is already registered
 * DevAttrReg
 * RFC 4171 Section 5.6.5.5 indicated SCN-port-tag (23) needed to be
 * included in the registration
 * Also need to register ESI-port-tag (20) see Section 6.3.5
 */
static int
isns_dev_attr_reg(int so, tgt_node_t *tgt, char *node, char *alias)
{
	isns_pdu_t	*cmd = NULL;
	isns_rsp_t	*rsp = NULL;
	uint32_t	flags = 0;
	int		ret = 0;
	Boolean_t	found = False;
	tgt_node_t	*src = NULL;
	char		*src_nm = NULL;

	queue_prt(mgmtq, Q_ISNS_DBG, "ISNS_DEV_ATTR_REG");

	if ((so = isns_open(isns_args.server)) == -1) {
		return (-1);
	}

	if (num_reg == 0) {
		flags |= ISNS_FLAG_REPLACE_REG;
	}

	if (isns_create_pdu(ISNS_DEV_ATTR_REG, flags, &cmd) != 0) {
		return (-1);
	}

	if (num_reg == 0) {
		/* add new node to source attribute */
		if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
		    STRLEN(node), node, 0) != 0) {
			goto error;
		}
	} else {
		/* find a registered node to use */
		do {
			src = find_next_tgt(src, &src_nm);
			if (src == NULL) {
				syslog(LOG_ALERT, "ISNS out of sync\n");
				goto error;
			}
			if (tgt == src) {
				free(src_nm);
				src_nm = NULL;
				continue;
			} else {
				found = True;
			}
		} while (found == False);

		if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
		    STRLEN(src_nm), src_nm, 0) != 0) {
			goto error;
		}
	}

	/* add message key attribute */
	if (isns_append_attr(cmd, ISNS_EID_ATTR_ID,
	    STRLEN(isns_args.entity), isns_args.entity, 0) != 0) {
		goto error;
	}

	/* add delimiter */
	if (isns_append_attr(cmd, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0) != 0) {
		goto error;
	}

	/* add operation attributes */

	/* entity id */
	if (isns_append_attr(cmd, ISNS_EID_ATTR_ID,
	    STRLEN(isns_args.entity), isns_args.entity, 0) != 0) {
		goto error;
	}

	/* entity type */
	if (isns_append_attr(cmd, ISNS_ENTITY_PROTOCOL_ATTR_ID,
	    ISNS_ENTITY_TYP_SZ, NULL, ISNS_ENTITY_PROTOCOL_ISCSI) != 0) {
		goto error;
	}

	/*
	 * Register entity portal properties the 1st time
	 */
	if (num_reg == 0) {
		/* portal ip-addr */
		if (isns_append_attr(cmd, ISNS_PORTAL_IP_ADDR_ATTR_ID,
		    eid_ip.ai_addrlen, (void *)&eid_ip.ip_adr,
		    eid_ip.ip_len) != 0) {
			goto error;
		}

		/* portal port */
		if (isns_append_attr(cmd, ISNS_PORTAL_PORT_ATTR_ID,
		    ISNS_PORT_SZ, NULL, iscsi_port) != 0) {
			goto error;
		}

		/* ESI interval */
		if (isns_append_attr(cmd, ISNS_ESI_INTERVAL_ATTR_ID,
		    ISNS_ESI_TICK_SZ, NULL, 10) != 0) {
			goto error;
		}

		/* scn port */
		if (isns_append_attr(cmd, ISNS_SCN_PORT_ATTR_ID,
		    ISNS_PORT_SZ, NULL, scn_port) != 0) {
			goto error;
		}

		/* esi port */
		if (isns_append_attr(cmd, ISNS_ESI_PORT_ATTR_ID,
		    ISNS_PORT_SZ, NULL, scn_port) != 0) {
			goto error;
		}
	}

	/* iscsi node name */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(node), node, 0) != 0) {
		goto error;
	}

	/* iscsi node type */
	if (isns_append_attr(cmd, ISNS_ISCSI_NODE_TYPE_ATTR_ID,
	    ISNS_NODE_TYP_SZ, NULL, ISNS_TARGET_NODE_TYPE) != 0) {
		goto error;
	}

	/* iscsi node alias */
	if (isns_append_attr(cmd, ISNS_ISCSI_ALIAS_ATTR_ID,
	    STRLEN(alias), alias, 0) != 0) {
		goto error;
	}

	/* PGT */
	if (append_tpgt(tgt, cmd) != 0) {
		goto error;
	}

	/* send pdu */
	if (isns_send(so, cmd) == -1) {
		goto error;
	}

	/* get isns response */
	if (isns_recv(so, &rsp) == -1) {
		goto error;
	}

	/* process response */
	if ((ret = process_rsp(cmd, rsp)) == 0) {
		num_reg++;
	}

error:
	/* Free all resouces here */
	if (cmd)
		isns_free_pdu(cmd);
	if (rsp)
		isns_free_pdu(rsp);
	if (src_nm)
		free(src_nm);
	return (ret);
}

/*
 * DevAttrQry for iscsi initiator
 * See RFC 4171 Sect. 5.6.5.2 for query detail
 */
static int
isns_dev_attr_qry(int so, char *target, char *initiator)
{
	isns_pdu_t	*cmd;
	isns_rsp_t	*rsp;
	uint32_t	flags = 0;
	int		ret = -1;
	size_t		remain;
	isns_tlv_t	*tlv;
	uint8_t		*ptr;

	queue_prt(mgmtq, Q_ISNS_DBG, "ISNS_DEV_ATTR_QRY");

	if (isns_create_pdu(ISNS_DEV_ATTR_QRY, flags, &cmd) != 0) {
		return (-1);
	}

	/* source attribute */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(target), target, 0) == -1) {
		goto error;
	}

	/* message key attribute */
	/* iscsi initiator node type */
	if (isns_append_attr(cmd, ISNS_ISCSI_NODE_TYPE_ATTR_ID,
	    ISNS_NODE_TYP_SZ, NULL, ISNS_INITIATOR_NODE_TYPE) == -1) {
		goto error;
	}

	/* delimiter */
	if (isns_append_attr(cmd, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0) == -1) {
		goto error;
	}

	/*
	 * operating attributes
	 * Query Iscsi initiator with zero length TLV operating
	 * attribute
	 */

	/* iscsi name */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    0, NULL, 0) != 0) {
		goto error;
	}

	if (isns_send(so, cmd) == -1) {
		syslog(LOG_ERR, "isns_dev_attr_qry fails isns_send");
		goto error;
	}

	/* recv response */
	if (isns_recv(so, &rsp) == -1) {
		syslog(LOG_ERR, "isns_dev_attr_qry fails isns_recv ");
		goto error;
	}

	/* process response */
	if ((ret = process_rsp(cmd, rsp)) == 0) {
		/* compare initiator name to the response, success if found */
		/* subtract out status word */
		remain = rsp->pdu_len - ISNS_STATUS_SZ;
		ptr = rsp->data;

		while (remain > 0) {
			/* LINTED */
			tlv = (isns_tlv_t *)ptr;

			/* debug only */
			print_ntoh_tlv(tlv);

			/* process tag-len-value */
			ntoh_tlv(tlv);
			/*
			 * let's process the data, only interested
			 * in iscsi name, skip everything else for
			 * now.
			 */
			if (tlv->attr_id == ISNS_ISCSI_NAME_ATTR_ID) {
				if (strncmp((char *)tlv->attr_value, initiator,
				    tlv->attr_len) == 0) {
					break;
				}
			}
			/* next tlv */
			remain -= ISNS_ATTR_SZ(tlv->attr_len);
			ptr += ISNS_ATTR_SZ(tlv->attr_len);
		}
		ret = (remain > 0) ? 1 : 0;
	}

error:
	if (cmd)
		isns_free_pdu(cmd);
	if (rsp)
		isns_free_pdu(rsp);
	return (ret);
}

/*
 * SCNReg
 * See RFC 4171 Section 5.6.5.5
 */
static int
isns_scn_reg(int so, char *node)
{
	isns_pdu_t	*cmd;
	isns_rsp_t	*rsp;
	uint32_t	flags = 0;
	uint32_t	bitmap = 0;
	int		ret = -1;

	queue_prt(mgmtq, Q_ISNS_DBG, "ISNS_SCN_REG");

	if (isns_create_pdu(ISNS_SCN_REG, flags, &cmd) != 0) {
		return (-1);
	}

	/* source attribute */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(node), node, 0) == -1) {
		goto error;
	}

	/* message key attribute */
	/* iscsi initiator node name */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(node), node, 0) != 0) {
		goto error;
	}

	/* delimiter */
	if (isns_append_attr(cmd, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0) == -1) {
		goto error;
	}

	/* SCN bitmap */
	bitmap = ISNS_INIT_SELF_INFO_ONLY | ISNS_OBJ_REMOVED |
	    ISNS_OBJ_ADDED | ISNS_OBJ_UPDATED;
	if (isns_append_attr(cmd, ISNS_ISCSI_SCN_BITMAP_ATTR_ID,
	    ISNS_SCN_BITMAP_SZ, NULL, bitmap) == -1) {
		goto error;
	}

	if (isns_send(so, cmd) == -1) {
		syslog(LOG_ERR, "isns_scn_reg fails isns_send");
		goto error;
	}

	if (isns_recv(so, &rsp) == -1) {
		syslog(LOG_ERR, "isns_scn_reg fails isns_recv ");
		goto error;
	}

	/* process response */
	if (process_rsp(cmd, rsp) == 0) {
		ret = 0;
	}

error:
	if (cmd)
		isns_free_pdu(cmd);
	if (rsp)
		isns_free_pdu(rsp);
	return (ret);
}


/*
 * SCNDereg
 */
static int
isns_scn_dereg(int so, char *node)
{
	isns_pdu_t	*cmd = NULL;
	isns_rsp_t	*rsp = NULL;
	uint32_t	flags = 0;
	int		ret = -1;

	queue_prt(mgmtq, Q_ISNS_DBG, "ISNS_SCN_DEREG");

	if (isns_create_pdu(ISNS_SCN_DEREG, flags, &cmd) != 0) {
		return (-1);
	}

	/* source attribute */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(node), node, 0) == -1) {
		goto error;
	}

	/* message key attribute */
	/* iscsi initiator node name */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(node), node, 0) != 0) {
		goto error;
	}

	if (isns_append_attr(cmd, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0) == -1) {
		goto error;
	}

	if (isns_send(so, cmd) == -1) {
		syslog(LOG_ERR, "isns_scn_reg fails isns_send");
		goto error;
	}

	if (isns_recv(so, &rsp) == -1) {
		syslog(LOG_ERR, "isns_scn_reg fails isns_recv ");
		goto error;
	}

	/* process response */
	if (process_rsp(cmd, rsp) == 0) {
		ret = 0;
	}

error:
	if (cmd)
		isns_free_pdu(cmd);
	if (rsp)
		isns_free_pdu(rsp);
	return (ret);
}

/*
 * isns_reg is called to register new target
 */
int
isns_reg(char *targ)
{
	int		so;
	tgt_node_t	*tgt;
	char		*iqn = NULL;

	if (isns_server_connection_thr_running == False) {
		syslog(LOG_ERR,
		    "isns_reg: iSNS discovery is not running."
		    " Check the previous iSNS initialization error.");
		return (-1);
	}

	if ((so = isns_open(isns_args.server)) == -1) {
		syslog(LOG_ERR, "isns_reg failed with server: %s",
		    isns_args.server);
		return (-1);
	}

	/*
	 * Open targets_config and devAttrReg all nodes
	 */
	if ((tgt = find_tgt_by_name(targ, &iqn)) != NULL) {
		if (isns_dev_attr_reg(so, tgt, iqn, tgt->x_value) != 0) {
			syslog(LOG_ALERT, "ISNS registration failed %s\n",
			    tgt->x_value);
			goto error;
		}
		if (isns_scn_reg(so, iqn) == -1) {
			syslog(LOG_ERR, "ISNS SCN register failed\n");
		}
	}

error:
	if (iqn)
		free(iqn);
	isns_close(so);
	return (0);
}


/*
 * Register all iscsi target nodes from the XML database
 * Alway use the ISNS_FLAG_REPLACE_REG flag
 */
int
isns_reg_all()
{
	int so;
	uint32_t	flags = ISNS_FLAG_REPLACE_REG;
	isns_pdu_t	*cmd = NULL;
	isns_rsp_t	*rsp = NULL;
	char		*n = NULL;
	char		*a = NULL;
	char		alias[MAXNAMELEN];
	char		iname[MAXNAMELEN];
	tgt_node_t	*tgt = NULL;
	int		ret = -1;
	int		tgt_cnt = 0;

	if (isns_server_connection_thr_running == False) {
		syslog(LOG_ERR,
		    "isns_reg_all: iSNS discovery is not running."
		    " Check the previous iSNS initialization error.");
		return (-1);
	}

	/*
	 * get the 1st target and use it for the source attribute
	 */
	if ((tgt = tgt_node_next_child(targets_config, XML_ELEMENT_TARG, tgt))
	    == NULL) {
		return (0);
	}
	if (tgt->x_value == NULL) {
		syslog(LOG_ALERT, "ISNS: target with NULL local name\n");
		return (-1);
	}
	if (tgt_find_value_str(tgt, XML_ELEMENT_INAME, &n)
	    == FALSE) {
		syslog(LOG_ALERT, "ISNS: no XML_ELEMENT_INAME found\n");
		return (-1);
	}
	(void) strcpy(iname, n);
	free(n);
	if ((so = isns_open(isns_args.server)) == -1) {
		syslog(LOG_ALERT, "ISNS: fails to connect to %s\n",
		    isns_args.server);
		return (-1);
	}

	if (isns_create_pdu(ISNS_DEV_ATTR_REG, flags, &cmd) != 0) {
		goto error;
	}

	/* source attribute */
	if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
	    STRLEN(iname), iname, 0) != 0) {
		goto error;
	}

	/* add message key attribute */
	if (isns_append_attr(cmd, ISNS_EID_ATTR_ID,
	    STRLEN(isns_args.entity), isns_args.entity, 0) != 0) {
		goto error;
	}

	/* add delimiter */
	if (isns_append_attr(cmd, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0) != 0) {
		goto error;
	}

	/* entity id */
	if (isns_append_attr(cmd, ISNS_EID_ATTR_ID,
	    STRLEN(isns_args.entity), isns_args.entity, 0) != 0) {
		goto error;
	}

	/* entity type */
	if (isns_append_attr(cmd, ISNS_ENTITY_PROTOCOL_ATTR_ID,
	    ISNS_ENTITY_TYP_SZ, NULL, ISNS_ENTITY_PROTOCOL_ISCSI) != 0) {
		goto error;
	}

	/* portal ip-addr */
	if (isns_append_attr(cmd, ISNS_PORTAL_IP_ADDR_ATTR_ID,
	    eid_ip.ai_addrlen, (void *)&eid_ip.ip_adr,
	    eid_ip.ip_len) != 0) {
		goto error;
	}

	/* portal port */
	if (isns_append_attr(cmd, ISNS_PORTAL_PORT_ATTR_ID,
	    ISNS_PORT_SZ, NULL, iscsi_port) != 0) {
		goto error;
	}

	/* ESI interval */
	if (isns_append_attr(cmd, ISNS_ESI_INTERVAL_ATTR_ID,
	    ISNS_ESI_TICK_SZ, NULL, 10) != 0) {
		goto error;
	}


	/* scn port */
	if (isns_append_attr(cmd, ISNS_SCN_PORT_ATTR_ID,
	    ISNS_PORT_SZ, NULL, scn_port) != 0) {
		goto error;
	}

	/* esi port */
	if (isns_append_attr(cmd, ISNS_ESI_PORT_ATTR_ID,
	    ISNS_PORT_SZ, NULL, scn_port) != 0) {
		goto error;
	}

	/*
	 * Open targets_config and devAttrReg all nodes
	 */
	tgt = NULL;
	while ((tgt = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    tgt)) != NULL) {
		if (tgt->x_value == NULL) {
			syslog(LOG_ALERT, "ISNS: target with NULL name\n");
			continue;
		}
		/* use this value as alias if alias is not set */
		(void) strcpy(alias, tgt->x_value);

		if (tgt_find_value_str(tgt, XML_ELEMENT_INAME, &n)
		    == FALSE) {
			continue;
		}
		(void) strcpy(iname, n);
		free(n);

		/* find alias */
		if (tgt_find_value_str(tgt, XML_ELEMENT_ALIAS, &a)
		    == TRUE) {
			(void) strcpy(alias, a);
			free(a);
		}

		tgt_cnt++;		/* increment target count */

		/* operation attributes */
		if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
		    STRLEN(iname), iname, 0) != 0) {
			goto error;
		}
		if (isns_append_attr(cmd, ISNS_ISCSI_NODE_TYPE_ATTR_ID,
		    4, NULL, ISNS_TARGET_NODE_TYPE) != 0) {
			goto error;
		}
		if (isns_append_attr(cmd, ISNS_ISCSI_ALIAS_ATTR_ID,
		    STRLEN(alias), alias, 0) != 0) {
			goto error;
		}

		if (append_tpgt(tgt, cmd) != 0) {
			goto error;
		}

	}

	/* send pdu */
	if (isns_send(so, cmd) == -1) {
		goto error;
	}

	/* get isns response */
	if (isns_recv(so, &rsp) == -1) {
		goto error;
	}

	/* process response */
	if (process_rsp(cmd, rsp) == 0) {
		ret = 0;
		num_reg = tgt_cnt;
		queue_prt(mgmtq, Q_ISNS_DBG, "DevAttrRegAll successful");
	} else {
		syslog(LOG_ALERT, "DevAttrReg failed");
	}

error:
	if (cmd)
		isns_free_pdu(cmd);
	if (rsp)
		isns_free_pdu(rsp);
	isns_close(so);
	return (ret);
}

/*
 * Deregister an iscsi target node
 */
int
isns_dereg(char *name)
{
	int so;
	int ret;

	if (isns_server_connection_thr_running == False) {
		syslog(LOG_ERR,
		    "isns_dereg: iSNS discovery is not running."
		    " Check the previous iSNS initialization error.");
		return (-1);
	}

	if ((so = isns_open(isns_args.server)) == -1) {
		return (-1);
	}

	ret = isns_dev_attr_dereg(so, name);

	isns_close(so);
	return (ret);
}

/*
 * Update an existing iscsi target property
 */
int
isns_dev_update(char *targ, uint32_t mods)
{
	int		so;
	int		flags = 0;	/* update only */
	char		*iname = NULL;
	char		*dummy = NULL;
	char		alias[MAXNAMELEN];
	tgt_node_t	*tgt = NULL;
	isns_pdu_t	*cmd;
	isns_rsp_t	*rsp;
	int		ret = -1;

	if (mods == 0)
		return (0);

	if (isns_server_connection_thr_running == False) {
		syslog(LOG_ERR,
		    "isns_dev_update: iSNS discovery is not running."
		    " Check the previous iSNS initialization error.");
		return (-1);
	}

	if ((tgt = find_tgt_by_name(targ, &iname)) != NULL) {
		if (tgt_find_value_str(tgt, XML_ELEMENT_ALIAS, &dummy) ==
		    True) {
			(void) strcpy(alias, dummy);
			free(dummy);
		} else
			(void) strcpy(alias, tgt->x_value);

		if ((so = isns_open(isns_args.server)) < 0) {
			goto error;
		}

		if (isns_create_pdu(ISNS_DEV_ATTR_REG, flags, &cmd)) {
			goto error;
		}
		/* source attr, msg key, delimiter */
		if (isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
		    STRLEN(iname), iname, 0) != 0) {
			goto error;
		}
		if (isns_append_attr(cmd, ISNS_EID_ATTR_ID,
		    STRLEN(isns_args.entity), isns_args.entity, 0) != 0) {
			goto error;
		}
		if (isns_append_attr(cmd, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0)
		    != 0) {
			goto error;
		}

		/*
		 * get current operating attributes, alias & portal group
		 * objects, these should be the only things that get change
		 */
		(void) isns_append_attr(cmd, ISNS_ISCSI_NAME_ATTR_ID,
		    STRLEN(iname), iname, 0);
		(void) isns_append_attr(cmd, ISNS_ISCSI_NODE_TYPE_ATTR_ID,
		    ISNS_NODE_TYP_SZ, NULL, ISNS_TARGET_NODE_TYPE);

		if (mods & ISNS_MOD_ALIAS)
		if (isns_append_attr(cmd, ISNS_ISCSI_ALIAS_ATTR_ID,
		    STRLEN(alias), alias, 0) != 0) {
			goto error;
		}

		if (mods & ISNS_MOD_TPGT)
			if (append_tpgt(tgt, cmd) != 0) {
				goto error;
			}

		if (isns_send(so, (isns_pdu_t *)cmd) < 0) {
			goto error;
		}

		if (isns_recv(so, &rsp) == -1) {
			goto error;
		}

		/* process response, if failed do a isns_reg_all */
		if ((ret = process_rsp(cmd, rsp)) == -1) {
			if (isns_reg_all() != 0 || isns_scn_reg_all() != 0) {
				syslog(LOG_ALERT, "ISNS register failed\n");
				goto error;
			}
			ret = 0;
		} else {
			if (isns_scn_reg(so, iname) == -1) {
				syslog(LOG_ERR, "ISNS SCN register failed\n");
				goto error;
			}
			ret = 0;
		}
	} else {
		syslog(LOG_ERR, "ISNS: fails to update target %s\n", alias);
	}

error:
	if (cmd)
		isns_free_pdu(cmd);
	if (rsp)
		isns_free_pdu(rsp);
	if (iname)
		free(iname);
	isns_close(so);
	return (ret);
}


/*
 * Deregister all iscsi target nodes from the XML database
 */
int
isns_dereg_all()
{
	return (isns_op_all(ISNS_DEV_DEREG));
}

int
isns_scn_reg_all()
{
	return (isns_op_all(ISNS_SCN_REG));
}

int
isns_scn_dereg_all()
{
	return (isns_op_all(ISNS_SCN_DEREG));
}

/*
 * Query an iscsi initiator node
 */
Boolean_t
isns_qry_initiator(char *target, char *initiator)
{
	int so;
	int ret;

	if (isns_server_connection_thr_running == False) {
		syslog(LOG_ERR,
		    "isns_qry_initiator: iSNS discovery is not running"
		    " Check the previous iSNS initialization error.");
		return (-1);
	}

	if ((so = isns_open(isns_args.server)) == -1) {
		syslog(LOG_ERR, "isns_qry failed");
		return (-1);
	}

	ret = isns_dev_attr_qry(so, target, initiator);

	isns_close(so);
	return (ret == 1 ? True : False);
}

Boolean_t
isns_enabled()
{
	Boolean_t	isns_access = False;
	char		*isns_srv = NULL;

	(void) tgt_find_value_boolean(main_config, XML_ELEMENT_ISNS_ACCESS,
	    &isns_access);
	/* get isns server info */
	if (isns_access == True) {
		if (tgt_find_value_str(main_config, XML_ELEMENT_ISNS_SERV,
		    &isns_srv) == True) {
			free(isns_srv);
			return (True);
		}
	}
	return (False);
}
