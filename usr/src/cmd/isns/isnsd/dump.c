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

/*
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 */

/* This file is getting large unexpectly, a lex & yacc */
/* implementation is expected. */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "isns_server.h"
#include "isns_htab.h"
#include "isns_msgq.h"
#include "isns_obj.h"
#include "isns_func.h"
#include "isns_dd.h"
#include "isns_cache.h"
#include "isns_pdu.h"

#ifdef DEBUG
/*
 * external variables
 */
extern const int NUM_OF_CHILD[MAX_OBJ_TYPE];
extern const int TYPE_OF_CHILD[MAX_OBJ_TYPE][MAX_CHILD_TYPE];
extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];
extern const int NUM_OF_REF[MAX_OBJ_TYPE_FOR_SIZE];

extern lookup_ctrl_t *setup_ddid_lcp(lookup_ctrl_t *, uint32_t);
extern lookup_ctrl_t *setup_ddsid_lcp(lookup_ctrl_t *, uint32_t);

/*
 * global variables
 */
int verbose_mc = 0;
int verbose_tc = 0;
int verbose_lock = 0;
int verbose_net = 0;
int verbose_parser = 0;

/*
 * local variables
 */
static void print_entity(char *, isns_obj_t *);
static void print_iscsi(char *, isns_obj_t *);
static void print_portal(char *, isns_obj_t *);
static void print_pg(char *, isns_obj_t *);
static void print_dd(char *, isns_obj_t *);
static void print_dds(char *, isns_obj_t *);
static void (*const print_func[MAX_OBJ_TYPE])(char *, isns_obj_t *) = {
	NULL,
	&print_entity,
	&print_iscsi,
	&print_portal,
	&print_pg,
	&print_dd,
	&print_dds
};
static int run_cmd(char *);

typedef struct {
	uint16_t func_id;
	char *fname;
} isnsp_fnames_t;
isnsp_fnames_t fnames[] = {
{ ISNS_DEV_ATTR_REG, "DevAttrReg" },
{ ISNS_DEV_ATTR_QRY, "DevAttrQry" },
{ ISNS_DEV_GET_NEXT, "DevGetNext" },
{ ISNS_DEV_DEREG, "DevDereg" },
{ ISNS_SCN_REG, "SCNReg" },
{ ISNS_SCN_DEREG, "SCNDereg" },
{ ISNS_DD_REG, "DDReg" },
{ ISNS_DD_DEREG, "DDDereg" },
{ ISNS_DDS_REG, "DDSReg" },
{ ISNS_DDS_DEREG, "DDSDereg" },
{ ISNS_SCN, "SCN" },
{ ISNS_ESI, "ESI" },
{ ISNS_HEARTBEAT, "Heartbeat" },
{ ISNS_DEV_ATTR_REG_RSP, "DevAttrRegRsp" },
{ ISNS_DEV_ATTR_QRY_RSP, "DevAttrQryRsp" },
{ ISNS_DEV_GET_NEXT_RSP, "DevGetNextRsp" },
{ ISNS_DEV_DEREG_RSP, "DevDeregRsp" },
{ ISNS_SCN_REG_RSP, "SCNRegRsp" },
{ ISNS_SCN_DEREG_RSP, "SCNDeregRsp" },
{ ISNS_SCN_RSP, "SCNRsp" },
{ ISNS_ESI_RSP, "ESIRsp" },
{ 0xFFFF, "Unknown" } };

static char *
get_func_name(
	uint16_t id
)
{
	int i = 0;
	isnsp_fnames_t *fp = &fnames[i ++];
	while (fp->func_id != 0xFFFF) {
		if (fp->func_id == id) {
			return (fp->fname);
		}
		fp = &fnames[i ++];
	}

	return ("UNKNOWN");
}

static char *
get_tlv_tag_name(
	uint32_t tag
)
{
	switch (tag) {
		case ISNS_DELIMITER_ATTR_ID:
			return ("Delimiter");
		case ISNS_EID_ATTR_ID:
			return ("Entity Identifier");
		case ISNS_ENTITY_PROTOCOL_ATTR_ID:
			return ("Entity Protocol");
		case ISNS_ENTITY_REG_PERIOD_ATTR_ID:
			return ("Registration Period");
		case ISNS_TIMESTAMP_ATTR_ID:
			return ("Timestamp");
		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
			return ("Portal IP Address");
		case ISNS_PORTAL_PORT_ATTR_ID:
			return ("Portal TCP/UDP Port");
		case ISNS_PORTAL_NAME_ATTR_ID:
			return ("Portal Symbolic Name");
		case ISNS_ESI_INTERVAL_ATTR_ID:
			return ("ESI Interval");
		case ISNS_ESI_PORT_ATTR_ID:
			return ("ESI Port");
		case ISNS_SCN_PORT_ATTR_ID:
			return ("SCN Port");
		case ISNS_PORTAL_SEC_BMP_ATTR_ID:
			return ("Portal Security Bitmap");
		case ISNS_ISCSI_NAME_ATTR_ID:
			return ("iSCSI Name");
		case ISNS_ISCSI_NODE_TYPE_ATTR_ID:
			return ("iSCSI Node Type");
		case ISNS_ISCSI_ALIAS_ATTR_ID:
			return ("iSCSI Alias");
		case ISNS_ISCSI_AUTH_METHOD_ATTR_ID:
			return ("iSCSI Auth Method");
		case ISNS_ISCSI_SCN_BITMAP_ATTR_ID:
			return ("iSCSI SCN Bitmap");
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			return ("PG iSCSI Name");
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			return ("PG Portal IP Addr");
		case ISNS_PG_PORTAL_PORT_ATTR_ID:
			return ("PG Portal TCP/UDP Port");
		case ISNS_PG_TAG_ATTR_ID:
			return ("PG Tag (PGT)");
		case ISNS_PG_INDEX_ATTR_ID:
			return ("PG Index");
		case ISNS_DD_NAME_ATTR_ID:
			return ("DD Name");
		case ISNS_DD_ID_ATTR_ID:
			return ("DD Index");
		case ISNS_DD_ISCSI_INDEX_ATTR_ID:
			return ("DD ISCSI Node Index");
		case ISNS_DD_ISCSI_NAME_ATTR_ID:
			return ("DD ISCSI Node Name");
		case ISNS_DD_SET_NAME_ATTR_ID:
			return ("DDS Name");
		case ISNS_DD_SET_ID_ATTR_ID:
			return ("DDS Index");
		case ISNS_DD_SET_STATUS_ATTR_ID:
			return ("DDS Status");
		default:
			return ("Unknown");
	}
}

static void
dump_pdu(
	isns_pdu_t *pdu,
	int flag
)
{
	short ver, id, len, flags, xid, seq;

	uint8_t *payload = pdu->payload;
	isns_resp_t *resp;

	/* convert the data */
	if (flag) {
		ver = ntohs(pdu->version);
		id = ntohs(pdu->func_id);
		len = ntohs(pdu->payload_len);
		flags = ntohs(pdu->flags) & 0xFFFF;
		xid = ntohs(pdu->xid);
		seq = ntohs(pdu->seq);
	} else {
		ver = pdu->version;
		id = pdu->func_id;
		len = pdu->payload_len;
		flags = pdu->flags & 0xFFFF;
		xid = pdu->xid;
		seq = pdu->seq;
	}

	/* print the pdu header */
	printf("iSNSP Version: %d\n", ver);
	printf("Function ID: %s\n", get_func_name(id));
	printf("PDU Length: %d\n", len);
	printf("Flags: %x\n", flags);
	printf("    %d... .... .... .... : ISNS_FLAG_CLIENT\n",
	    ((flags & ISNS_FLAG_CLIENT) == 0) ? 0 : 1);
	printf("    .%d.. .... .... .... : ISNS_FLAG_SERVER\n",
	    ((flags & ISNS_FLAG_SERVER) == 0) ? 0 : 1);
	printf("    ..%d. .... .... .... : ISNS_FLAG_AUTH_BLK_PRESENTED\n",
	    ((flags & ISNS_FLAG_AUTH_BLK_PRESENTED) == 0) ? 0 : 1);
	printf("    ...%d .... .... .... : ISNS_FLAG_REPLACE_REG\n",
	    ((flags & ISNS_FLAG_REPLACE_REG) == 0) ? 0 : 1);
	printf("    .... %d... .... .... : ISNS_FLAG_LAST_PDU\n",
	    ((flags & ISNS_FLAG_LAST_PDU) == 0) ? 0 : 1);
	printf("    .... .%d.. .... .... : ISNS_FLAG_FIRST_PDU\n",
	    ((flags & ISNS_FLAG_FIRST_PDU) == 0) ? 0 : 1);
	printf("Transaction ID: %d\n", xid);
	printf("Sequence ID: %d\n", seq);

	printf("Payload: ...\n");
	if (id & ISNS_RSP_MASK) {
		resp = (isns_resp_t *)payload;
		printf("    ErrorCode: %d\n", ntohl(resp->status));
		len -= 4;
		payload += 4;
	}

	/* print the payload */
	while (len > 0) {
		isns_tlv_t *tlvp;
		int t, l;
		uint8_t *v;
		char *s;
		int i;
		in6_addr_t *ip;
		char pbuff[256] = { 0 };

		tlvp = (isns_tlv_t *)payload;

		/* convert the data */
		t = ntohl(tlvp->attr_id);
		l = ntohl(tlvp->attr_len);
		v = &(tlvp->attr_value[0]);

		/* print payload */
		if (l > 0) {
			printf("%s: ", get_tlv_tag_name(t));
			switch (t) {
				case ISNS_EID_ATTR_ID:
				case ISNS_ISCSI_NAME_ATTR_ID:
				case ISNS_ISCSI_ALIAS_ATTR_ID:
				case ISNS_ISCSI_AUTH_METHOD_ATTR_ID:
				case ISNS_PG_ISCSI_NAME_ATTR_ID:
				case ISNS_DD_NAME_ATTR_ID:
				case ISNS_DD_SET_NAME_ATTR_ID:
					s = (char *)v;
					printf("%s\n", s);
					break;
				case ISNS_ENTITY_PROTOCOL_ATTR_ID:
					i = ntohl(*(uint32_t *)v);
					printf("%s (%d)\n",
					    ((i == 1) ? "No Protocol" :
					    ((i == 2) ? "iSCSI" :
					    ((i == 3) ? "iFCP" :
					    "Others"))),
					    i);
					break;
				case ISNS_PORTAL_IP_ADDR_ATTR_ID:
				case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
					ip = (in6_addr_t *)v;
					inet_ntop(AF_INET6, (void *)ip,
					    pbuff, sizeof (pbuff));
					printf("%s\n", pbuff);
					break;
				case ISNS_PORTAL_PORT_ATTR_ID:
				case ISNS_ESI_PORT_ATTR_ID:
				case ISNS_SCN_PORT_ATTR_ID:
					i = ntohl(*(uint32_t *)v);
					printf("%d\n", (i & 0x0000FFFF));
					printf("    .... .... %d... .... : "
					    "0=TCP\n",
					    ((i & 0x10000) == 0) ? 0 : 1);
					break;
				case ISNS_ISCSI_NODE_TYPE_ATTR_ID:
					i = ntohl(*(uint32_t *)v);
					printf("0x%x\t", i);
					if (i & ISNS_CONTROL_NODE_TYPE) {
						printf("Control ");
					}
					if (i & ISNS_INITIATOR_NODE_TYPE) {
						printf("Initiator ");
					}
					if (i & ISNS_TARGET_NODE_TYPE) {
						printf("Target ");
					}
					printf("\n");
					break;
				case ISNS_PG_TAG_ATTR_ID:
				default:
					i = ntohl(*(uint32_t *)v);
					printf("%d\n", i);
					break;
			}
			printf("    Attribute Tag: %s (%d)\n",
			    get_tlv_tag_name(t), t);
			printf("    Attribute Length: %d\n", l);
		} else {
			printf("%s: (%d)\n", get_tlv_tag_name(t), t);
		}

		len -= (sizeof (uint32_t) * 2 + l);
		payload += (sizeof (uint32_t) * 2 + l);
	}
}

void
dump_pdu1(
	isns_pdu_t *pdu
)
{
	if (verbose_net) {
		printf("### PDU RECEIVED ###\n");
		dump_pdu(pdu, 0);
	}
}

void
dump_pdu2(
	isns_pdu_t *pdu
)
{
	if (verbose_net) {
		printf("### PDU SENT ###\n");
		dump_pdu(pdu, 1);
	}
}

void
dump_db(
)
{
#if 0
	isns_list_t *list, *lista, *listb;
	isns_dds_t *dds;
	isns_dd_t *dd;
	isns_iscsi2_t *iscsi2;

	printf("### DUMP DATABASE ###\n");
	/* dump dds(s) */
	list = dds_list;
	while (list != NULL) {
		dds = list->obj.dds;
		printf("[DDS:%d]%s(%s)\n", dds->id, dds->name,
		    dds->status ? "enabled" : "disabled");
		lista = dds->dd_list;
		/* dd(s) that belong to this dds */
		while (lista != NULL) {
			dd = lista->obj.dd;
			printf("\t[DD:%d]%s\n", dd->id, dd->name);
			lista = lista->next;
		}
		list = list->next;
	}
	/* dump dd(s) */
	list = dd_list;
	while (list != NULL) {
		dd = list->obj.dd;
		printf("[DD:%d]%s\n", dd->id, dd->name);
		/* dds(s) this dd belongs to */
		lista = dd->dds_list;
		while (lista != NULL) {
			dds = lista->obj.dds;
			printf("\t[DDS:%d]%s\n", dds->id, dds->name);
			lista = lista->next;
		}
		/* node(s) that this dd have */
		listb = dd->iscsi_list;
		while (listb != NULL) {
			iscsi2 = listb->obj.iscsi2;
			printf("\t[ISCSI:%d]%s\n", iscsi2->id, iscsi2->name);
			listb = listb->next;
		}
		list = list->next;
	}
	/* dump node(s) */
	list = iscsi_list;
	while (list != NULL) {
		iscsi2 = list->obj.iscsi2;
		printf("[ISCSI:%d]%s\n", iscsi2->id, iscsi2->name);
		lista = iscsi2->dd_list;
		/* dd(s) that this node belongs to */
		while (lista != NULL) {
			dd = lista->obj.dd;
			printf("\t[DD:%d]%s\n", dd->id, dd->name);
			lista = lista->next;
		}
		list = list->next;
	}
#endif
}

static void
test_cli_help(
)
{
	printf("list          - list all of storage node.\n");
	printf("list dd  [id] - list all of dd or one with member.\n");
	printf("list dds [id] - list all of dd-set or one with member.\n");

	printf("\n");
	printf("new dd  <name>  - create a dd with name.\n");
	printf("new dds <name>  - create a dd-set with name.\n");
	printf("new ddn  <id> <name>  - create a dd with id and name.\n");
	printf("new ddsn <id> <name>  - create a dd-set with id and name.\n");
	printf("del dd   <id>   - delete a dd.\n");
	printf("del dds  <id>   - delete a dd-set.\n");

	printf("\n");
	printf("add dd   <dd_id>  <node_name> - add a node to dd.\n");
	printf("add ddn  <dd_id>  <node_id>   - add a node to dd.\n");
	printf("add ddsn <dds_id> <dd_id>     - add a dd to dd-set.\n");
	printf("remove dd   <dd_id> <node_name> - remove a node from dd.\n");
	printf("remove ddn  <dd_id> <node_id>   - remove a node from dd.\n");
	printf("remove ddsn <dds_id> <dd_id>    - remove a dd from dd-set.\n");

	printf("\n");
	printf("enable  <dds_id> - enable a dd-set.\n");
	printf("disable <dds_id> - disable a dd-set.\n");

	printf("\n");
	printf("file <f> - loading command from a file.\n");
	printf("pause    - suspend batch until enter key is pressed.\n");

	printf("help   - print this help.\n");
	printf("quit   - stop iSNS server and quit.\n");
}

enum {
	CMD_LIST, CMD_LISTNE, CMD_LISTP, CMD_LISTPG,
	CMD_LISTDD, CMD_LISTDDS, CMD_LISTDDN, CMD_LISTDDSN,
	CMD_NEWDD, CMD_NEWDDS, CMD_NEWDDN, CMD_NEWDDSN,
	CMD_DELDD, CMD_DELDDS,
	CMD_ENABLE, CMD_DISABLE,
	CMD_ADDDD, CMD_ADDDDN, CMD_ADDDDSN,
	CMD_REMDD, CMD_REMDDN, CMD_REMDDSN,
	CMD_VIEW,
	CMD_FILE, CMD_PAUSE,
	CMD_HELP,
	CMD_VERBOSE_MEMORY, CMD_VERBOSE_NET,
	CMD_VERBOSE_PARSER, CMD_VERBOSE_TIME,
	CMD_VERBOSE_LOCK,
	CMD_QUIT,
	CMD_NONE, CMD_INVALID
};

static int
getcmd(
	int *argc, int *argv, char *cmd
)
{
	int j = 0;
	char tmp[256] = { 0 };
	*argc = 0;
	while (*cmd == ' ') cmd ++;

	if (*cmd == 0) {
		return (CMD_NONE);
	} else if (*cmd == '?') {
		return (CMD_HELP);
	}

	/* list, list dd, list dds, list dd 0 */
	if (strncmp(cmd, "list ", 5) == 0) {
		cmd += 5;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0) {
			return (CMD_LIST);
		} else if (*cmd == 'p') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_LISTP);
			}
		} else if (*cmd == 'g') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_LISTPG);
			}
		} else if (*cmd == 'e') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_LISTNE);
			}
		} else if (strncmp(cmd, "dds ", 4) == 0) {
			cmd += 4;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_LISTDDS);
			}
			j = 0;
			while (*cmd >= '0' && *cmd <= '9') {
				tmp[j++] = *cmd ++;
			}
			tmp[j] = 0;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0 && j > 0) {
				argv[(*argc)++] = atoi(tmp);
				return (CMD_LISTDDSN);
			}
		} else if (strncmp(cmd, "dd ", 3) == 0) {
			cmd += 3;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_LISTDD);
			}
			j = 0;
			while (*cmd >= '0' && *cmd <= '9') {
				tmp[j++] = *cmd ++;
			}
			tmp[j] = 0;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0 && j > 0) {
				argv[(*argc)++] = atoi(tmp);
				return (CMD_LISTDDN);
			}
		}
		return (CMD_INVALID);
	}

	/* view 0 */
	if (strncmp(cmd, "view ", 5) == 0) {
		cmd += 5;
		while (*cmd == ' ') cmd ++;
		j = 0;
		while (*cmd >= '0' && *cmd <= '9') {
			tmp[j++] = *cmd ++;
		}
		tmp[j] = 0;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0 && j > 0) {
			argv[(*argc)++] = atoi(tmp);
			return (CMD_VIEW);
		}
		return (CMD_INVALID);
	}

	/* add dd name */
	/* add ddn/ddsn id id */
	if (strncmp(cmd, "add ", 4) == 0) {
		int addcmd = CMD_INVALID;
		cmd += 4;
		while (*cmd == ' ') cmd ++;
		if (strncmp(cmd, "dd ", 3) == 0) {
			cmd += 3;
			addcmd = CMD_ADDDD;
		} else if (strncmp(cmd, "ddn ", 4) == 0) {
			cmd += 4;
			addcmd = CMD_ADDDDN;
		} else if (strncmp(cmd, "ddsn ", 5) == 0) {
			cmd += 5;
			addcmd = CMD_ADDDDSN;
		} else {
			return (CMD_INVALID);
		}
		while (*cmd == ' ') cmd ++;
		j = 0;
		while (*cmd >= '0' && *cmd <= '9') {
			tmp[j++] = *cmd ++;
		}
		tmp[j] = 0;
		if (j > 0) {
			argv[(*argc)++] = atoi(tmp);
		} else {
			return (CMD_INVALID);
		}
		while (*cmd == ' ') cmd ++;
		if (*cmd != 0) {
			switch (addcmd) {
			case CMD_ADDDDN:
			case CMD_ADDDDSN:
				j = 0;
				while (*cmd >= '0' && *cmd <= '9') {
					tmp[j++] = *cmd ++;
				}
				tmp[j] = 0;
				while (*cmd == ' ') cmd ++;
				if (*cmd == 0 && j > 0) {
					argv[(*argc)++] = atoi(tmp);
				} else {
					return (CMD_INVALID);
				}
				break;
			case CMD_ADDDD:
				j = strlen(cmd);
				while (j > 0) {
					/* get rid of trail blank space */
					if (cmd[j - 1] == ' ') {
						cmd[--j] = 0;
					} else {
						break;
					}
				}
				if (j > 0) {
					cmd[j] = 0;
					argv[(*argc)++] = (int)cmd;
				} else {
					return (CMD_INVALID);
				}
				break;
			}
			return (addcmd);
		}
		return (CMD_INVALID);
	}

	/* remove dd name */
	/* remove ddn/ddsn id id */
	if (strncmp(cmd, "remove ", 7) == 0) {
		int rmcmd = CMD_INVALID;
		cmd += 7;
		while (*cmd == ' ') cmd ++;
		if (strncmp(cmd, "dd ", 3) == 0) {
			cmd += 3;
			while (*cmd == ' ') cmd ++;
			rmcmd = CMD_REMDD;
		} else if (strncmp(cmd, "ddn ", 4) == 0) {
			cmd += 4;
			while (*cmd == ' ') cmd ++;
			rmcmd = CMD_REMDDN;
		} else if (strncmp(cmd, "ddsn ", 5) == 0) {
			cmd += 5;
			while (*cmd == ' ') cmd ++;
			rmcmd = CMD_REMDDSN;
		} else {
			return (CMD_INVALID);
		}
		j = 0;
		while (*cmd >= '0' && *cmd <= '9') {
			tmp[j++] = *cmd ++;
		}
		tmp[j] = 0;
		if (j > 0) {
			argv[(*argc)++] = atoi(tmp);
		} else {
			return (CMD_INVALID);
		}
		while (*cmd == ' ') cmd ++;
		if (*cmd != 0) {
			switch (rmcmd) {
			case CMD_REMDDN:
			case CMD_REMDDSN:
				j = 0;
				while (*cmd >= '0' && *cmd <= '9') {
					tmp[j++] = *cmd ++;
				}
				tmp[j] = 0;
				while (*cmd == ' ') cmd ++;
				if (*cmd == 0 && j > 0) {
					argv[(*argc)++] = atoi(tmp);
				} else {
					return (CMD_INVALID);
				}
				break;
			case CMD_REMDD:
				j = strlen(cmd);
				while (j > 0) {
					/* get rid of trail blank space */
					if (cmd[j - 1] == ' ') {
						cmd[--j] = 0;
					} else {
						break;
					}
				}
				if (j > 0) {
					cmd[j] = 0;
					argv[(*argc)++] = (int)cmd;
				} else {
					return (CMD_INVALID);
				}
				break;
			}
			return (rmcmd);
		}
		return (CMD_INVALID);
	}

	/* new dd, new dds */
	if (strncmp(cmd, "new ", 4) == 0) {
		int newcmd = CMD_INVALID;
		cmd += 4;
		while (*cmd == ' ') cmd ++;
		if (strncmp(cmd, "dd ", 3) == 0) {
			cmd += 3;
			newcmd = CMD_NEWDD;
		} else if (strncmp(cmd, "dds ", 4) == 0) {
			cmd += 4;
			newcmd = CMD_NEWDDS;
		} else if (strncmp(cmd, "ddn ", 4) == 0) {
			cmd += 4;
			newcmd = CMD_NEWDDN;
		} else if (strncmp(cmd, "ddsn ", 5) == 0) {
			cmd += 5;
			newcmd = CMD_NEWDDSN;
		}
		if (newcmd != CMD_INVALID) {
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (newcmd);
			}
			switch (newcmd) {
			case CMD_NEWDDN:
			case CMD_NEWDDSN:
				j = 0;
				while (*cmd >= '0' && *cmd <= '9') {
					tmp[j++] = *cmd ++;
				}
				tmp[j] = 0;
				if (*cmd == ' ' && j > 0) {
					argv[(*argc)++] = atoi(tmp);
				} else {
					return (CMD_INVALID);
				}
			case CMD_NEWDD:
			case CMD_NEWDDS:
				while (*cmd == ' ') cmd ++;
				if (*cmd != 0) {
					j = strlen(cmd);
				} else {
					j = 0;
				}
				while (j > 0) {
					/* get rid of trail blank space */
					if (cmd[j - 1] == ' ') {
						cmd[--j] = 0;
					} else {
						break;
					}
				}
				if (j > 0) {
					cmd[j] = 0;
					argv[(*argc)++] = (int)cmd;
				}
			}
			return (newcmd);
		}
		return (CMD_INVALID);
	}

	/* del dd, del dds, disable 0 */
	if (strncmp(cmd, "del ", 4) == 0) {
		int delcmd = CMD_INVALID;
		cmd += 4;
		while (*cmd == ' ') cmd ++;
		if (strncmp(cmd, "dds ", 4) == 0) {
			cmd += 4;
			delcmd = CMD_DELDDS;
		} else if (strncmp(cmd, "dd ", 3) == 0) {
			cmd += 3;
			delcmd = CMD_DELDD;
		}
		if (delcmd != CMD_INVALID) {
			while (*cmd == ' ') cmd ++;
			j = 0;
			while (*cmd >= '0' && *cmd <= '9') {
				tmp[j++] = *cmd ++;
			}
			tmp[j] = 0;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0 && j > 0) {
				argv[(*argc)++] = atoi(tmp);
				return (delcmd);
			}
		}
		return (CMD_INVALID);
	}

	/* enable 0 */
	if (strncmp(cmd, "enable ", 7) == 0) {
		cmd += 7;
		while (*cmd == ' ') cmd ++;
		j = 0;
		while (*cmd >= '0' && *cmd <= '9') {
			tmp[j++] = *cmd ++;
		}
		tmp[j] = 0;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0 && j > 0) {
			argv[(*argc)++] = atoi(tmp);
			return (CMD_ENABLE);
		}
		return (CMD_INVALID);
	}

	/* disable 0 */
	if (strncmp(cmd, "disable ", 8) == 0) {
		cmd += 8;
		while (*cmd == ' ') cmd ++;
		j = 0;
		while (*cmd >= '0' && *cmd <= '9') {
			tmp[j++] = *cmd ++;
		}
		tmp[j] = 0;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0 && j > 0) {
			argv[(*argc)++] = atoi(tmp);
			return (CMD_DISABLE);
		}
		return (CMD_INVALID);
	}

	/* file */
	if (strncmp(cmd, "file ", 5) == 0) {
		cmd += 5;
		while (*cmd == ' ') cmd ++;
		if (*cmd != 0) {
			j = strlen(cmd);
		} else {
			j = 0;
		}
		while (j > 0) {
			/* get rid of trail blank space */
			if (cmd[j - 1] == ' ') {
				cmd[--j] = 0;
			} else {
				break;
			}
		}
		if (j > 0) {
			cmd[j] = 0;
			argv[(*argc)++] = (int)cmd;
			return (CMD_FILE);
		}
		return (CMD_INVALID);
	}

	/* pause */
	if (strncmp(cmd, "pause ", 6) == 0) {
		cmd += 6;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0) {
			return (CMD_PAUSE);
		}
		return (CMD_INVALID);
	}

	/* help */
	if (strncmp(cmd, "help ", 5) == 0) {
		cmd += 5;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0) {
			return (CMD_HELP);
		}
		return (CMD_INVALID);
	}

	/* verbose */
	if (strncmp(cmd, "verbose ", 8) == 0) {
		cmd += 8;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0) {
			return (CMD_VERBOSE_PARSER);
		} else if (*cmd == 'm') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_VERBOSE_MEMORY);
			}
		} else if (*cmd == 'n') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_VERBOSE_NET);
			}
		} else if (*cmd == 'p') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_VERBOSE_PARSER);
			}
		} else if (*cmd == 't') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_VERBOSE_TIME);
			}
		} else if (*cmd == 'l') {
			cmd ++;
			while (*cmd == ' ') cmd ++;
			if (*cmd == 0) {
				return (CMD_VERBOSE_LOCK);
			}
		}
		return (CMD_INVALID);
	}

	/* quit */
	if (strncmp(cmd, "quit ", 5) == 0) {
		cmd += 5;
		while (*cmd == ' ') cmd ++;
		if (*cmd == 0) {
			return (CMD_QUIT);
		}
		return (CMD_INVALID);
	}

	return (CMD_INVALID);
}

static void
print_entity(
	char *ident,
	isns_obj_t *obj
)
{
	uint32_t uid;
	uchar_t *eid;
	uint32_t *cuid;
	int i, num;

	eid = obj->attrs[
	    ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID)].value.ptr;
	uid = get_obj_uid(obj);

	if (ident != NULL) {
		printf("%s%d\t%s\n", ident, uid, (const char *)eid);
	} else {
		printf("%d\t%s\n", uid, (const char *)eid);
	}

	i = 0;
	while (i < NUM_OF_CHILD[obj->type]) {
		cuid = get_child_n(obj, i);
		if (ident != NULL) {
			printf("%s\t%s%d:", "child", i);
		} else {
			printf("\t%s%d:", "child", i);
		}
		if (cuid != NULL) {
			num = *cuid ++;
		} else {
			num = 0;
		}
		while (num > 0) {
			printf("\t%d", *cuid ++);
			num --;
		}
		printf("\n");
		i ++;
	}
}

static void
print_iscsi(
	char *ident,
	isns_obj_t *obj
)
{
	uchar_t *name = obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)]
	    .value.ptr;
	uchar_t *alias = obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_ALIAS_ATTR_ID)]
	    .value.ptr;
	uint32_t type = obj->attrs[
	    ATTR_INDEX_ISCSI(ISNS_ISCSI_NODE_TYPE_ATTR_ID)].value.ui;
	uint32_t uid = get_obj_uid(obj);
	uint32_t puid = get_parent_uid(obj);

	if (!alias) {
		alias = (uchar_t *)"-";
	}

	if (ident != NULL) {
		printf("%s%d[%d]\t%s\n", ident,
		    uid, puid, (const char *)name);
		printf("%s\t%s", ident, alias);
	} else {
		printf("%d[%d]\t%s\n",
		    uid, puid, (const char *)name);
		printf("\t%s", alias);
	}
	if (IS_TYPE_TARGET(type)) {
		printf("\tTarget");
	}
	if (IS_TYPE_INITIATOR(type)) {
		printf("\tInitiator");
	}
	if (IS_TYPE_CONTROL(type)) {
		printf("\tControl");
	}
	if (IS_TYPE_UNKNOWN(type)) {
		printf("\t-");
	}
	printf("\n");
}

static void
print_portal(
	char *ident,
	isns_obj_t *obj
)
{
	char pbuff[256] = { 0 };
	in6_addr_t *ip = obj->attrs[
	    ATTR_INDEX_PORTAL(ISNS_PORTAL_IP_ADDR_ATTR_ID)].value.ip;
	uint32_t port = obj->attrs[
	    ATTR_INDEX_PORTAL(ISNS_PORTAL_PORT_ATTR_ID)].value.ui;
	uint32_t uid = get_obj_uid(obj);
	uint32_t puid = get_parent_uid(obj);

	inet_ntop(AF_INET6, (void *)ip, pbuff, sizeof (pbuff));
	if (ident != NULL) {
		printf("%s%d[%d]\t%s:%d", ident,
		    uid, puid, pbuff, PORT_NUMBER(port));
	} else {
		printf("%d[%d]\t%s:%d",
		    uid, puid, pbuff, PORT_NUMBER(port));
	}
	printf(" %s\n", IS_PORT_UDP(port) ? "UDP" : "TCP");
}

static void
print_pg(
	char *ident,
	isns_obj_t *obj
)
{
	uint32_t ref;
	int i;

	char pbuff[256] = { 0 };
	uchar_t *name = obj->attrs[ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID)]
	    .value.ptr;
	in6_addr_t *ip = obj->attrs[
	    ATTR_INDEX_PG(ISNS_PG_PORTAL_IP_ADDR_ATTR_ID)].value.ip;
	uint32_t port = obj->attrs[
	    ATTR_INDEX_PG(ISNS_PG_PORTAL_PORT_ATTR_ID)].value.ui;
	uint32_t tag = obj->attrs[
	    ATTR_INDEX_PG(ISNS_PG_TAG_ATTR_ID)].value.ui;
	uint32_t uid = get_obj_uid(obj);
	uint32_t puid = get_parent_uid(obj);

	inet_ntop(AF_INET6, (void *)ip, pbuff, sizeof (pbuff));
	if (ident != NULL) {
		printf("%s%d[%d]\t[%d] %s\n", ident,
		    uid, puid, tag, (const char *)name);
		printf("%s\t%s:%d", ident, pbuff, PORT_NUMBER(port));
	} else {
		printf("%d[%d]\t[%d] %s\n",
		    uid, puid, tag, (const char *)name);
		printf("\t%s:%d", pbuff, PORT_NUMBER(port));
	}
	printf(" %s\n", IS_PORT_UDP(port) ? "UDP" : "TCP");

	if (NUM_OF_REF[obj->type] > 0) {
		if (ident != NULL) {
			printf("%s\t%s:", "ref");
		} else {
			printf("\t%s:", "ref");
		}
	}
	i = 0;
	while (i < NUM_OF_REF[obj->type]) {
		ref = get_ref_n(obj, i);
		printf("\t%d", ref);
		i ++;
	}
	if (i > 0) {
		printf("\n");
	}
}

static void
print_dd(
	char *ident,
	isns_obj_t *obj
)
{
	uchar_t *name = obj->attrs[ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID)]
	    .value.ptr;
	uint32_t uid = obj->attrs[UID_ATTR_INDEX[OBJ_DD]].value.ui;

	if (ident != NULL) {
		printf("%s%d\t%s\n", ident, uid, (const char *)name);
	} else {
		printf("%d\t%s\n", uid, (const char *)name);
	}
}

static void
print_dds(
	char *ident,
	isns_obj_t *obj
)
{
	uchar_t *name = obj->attrs[ATTR_INDEX_DDS(
	    ISNS_DD_SET_NAME_ATTR_ID)].value.ptr;
	uint32_t uid = obj->attrs[UID_ATTR_INDEX[OBJ_DDS]].value.ui;
	uint32_t enabled = obj->attrs[ATTR_INDEX_DDS(
	    ISNS_DD_SET_STATUS_ATTR_ID)].value.ui;

	if (ident != NULL) {
		printf("%s%d\t%s\t\t(%s)\n", ident, uid,
		    (const char *)name, enabled ? "enabled" : "disabled");
	} else {
		printf("%d\t%s\t\t(%s)\n", uid,
		    (const char *)name, enabled ? "enabled" : "disabled");
	}
}

void
print_object(
	char *ident,
	isns_obj_t *obj
)
{
	print_func[obj->type](ident, obj);
}

/*ARGSUSED*/
static int
cb_print_obj_n(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	print_func[obj->type](NULL, obj);

	return (0);
}

static void
list_pg(
)
{
	cache_dump_htab(OBJ_PG);
}

static void
list_portal(
)
{
	cache_dump_htab(OBJ_PORTAL);
}

static void
list_node(
)
{
	cache_dump_htab(OBJ_ISCSI);
}

static void
list_entity(
)
{
	cache_dump_htab(OBJ_ENTITY);
}

static void
list_dd(
)
{
	cache_dump_htab(OBJ_DD);
}

static void
list_ddn(
	uint32_t uid
)
{
	lookup_ctrl_t lc;

	bmp_t *p;
	uint32_t n;

	if (uid != 0) {
		setup_ddid_lcp(&lc, uid);
		cache_lookup(&lc, &uid, cb_print_obj_n);
	}

	if (uid != 0) {
		printf("--------------------------------\n");
		get_dd_matrix(uid, &p, &n);
		SET_UID_LCP(&lc, OBJ_ISCSI, 0);
		FOR_EACH_MEMBER(p, n, uid, {
			lc.data[0].ui = uid;
			cache_lookup(&lc, NULL, cb_print_obj_n);
		});
		free(p);
	} else {
		printf("no such dd.\n");
	}
}

static void
list_ddsn(
	uint32_t uid
)
{
	lookup_ctrl_t lc;

	bmp_t *p;
	uint32_t n;

	if (uid != 0) {
		setup_ddsid_lcp(&lc, uid);
		cache_lookup(&lc, &uid, cb_print_obj_n);
	}

	if (uid != 0) {
		printf("--------------------------------\n");
		get_dds_matrix(uid, &p, &n);
		SET_UID_LCP(&lc, OBJ_DD, 0);
		FOR_EACH_MEMBER(p, n, uid, {
			lc.data[0].ui = uid;
			cache_lookup(&lc, NULL, cb_print_obj_n);
		});
		free(p);
	} else {
		printf("no such dd-set.\n");
	}
}

static void
list_dds(
)
{
	cache_dump_htab(OBJ_DDS);
}

static void
new_dd_dds(
	int cmd_id,
	int argc,
	int *argv
)
{
	uint32_t buff[256];
	isns_pdu_t *pdu = (isns_pdu_t *)buff;
	uint8_t *payload = &pdu->payload[0];
	uint16_t payload_len = 0;
	isns_tlv_t *tlv;

	int len = 0;
	uint32_t uid = 0;
	char *name;

	conn_arg_t conn;

	pdu->version = ISNSP_VERSION;

	/* source attribute */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_ISCSI_NAME_ATTR_ID);
	tlv->attr_len = htonl(32);
	strcpy((char *)tlv->attr_value, "i am a control node.");
	payload += 8 + 32;
	payload_len += 8 + 32;

	/* key attributes */

	/* delimiter */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_DELIMITER_ATTR_ID);
	tlv->attr_len = htonl(0);
	payload += 8 + 0;
	payload_len += 8 + 0;

	/* operating attributes */
	switch (cmd_id) {
	case CMD_NEWDD:
		pdu->func_id = ISNS_DD_REG;
		if (argc == 1) {
			name = (char *)argv[0];
			len = strlen(name) + 1;
			len += 4 - (len % 4);
		}
		tlv = (isns_tlv_t *)payload;
		tlv->attr_id = htonl(ISNS_DD_NAME_ATTR_ID);
		tlv->attr_len = htonl(len);
		if (len > 0) {
			strcpy((char *)tlv->attr_value, name);
		}
		payload_len += 8 + len;
		break;
	case CMD_NEWDDS:
		pdu->func_id = ISNS_DDS_REG;
		if (argc == 1) {
			name = (char *)argv[0];
			len = strlen(name) + 1;
			len += 4 - (len % 4);
		}
		tlv = (isns_tlv_t *)payload;
		tlv->attr_id = htonl(ISNS_DD_SET_NAME_ATTR_ID);
		tlv->attr_len = htonl(len);
		if (len > 0) {
			strcpy((char *)tlv->attr_value, name);
		}
		payload_len += 8 + len;
		break;
	case CMD_NEWDDN:
		pdu->func_id = ISNS_DD_REG;
		switch (argc) {
		case 2:
			name = (char *)argv[1];
			len = strlen(name) + 1;
			len += 4 - (len % 4);
			/* FALLTHROUGH */
		case 1:
			uid = argv[0];
		}
		tlv = (isns_tlv_t *)payload;
		tlv->attr_id = htonl(ISNS_DD_NAME_ATTR_ID);
		tlv->attr_len = htonl(len);
		if (len > 0) {
			strcpy((char *)tlv->attr_value, name);
		}
		payload += 8 + len;
		payload_len += 8 + len;
		if (uid > 0) {
			tlv = (isns_tlv_t *)payload;
			tlv->attr_id = htonl(ISNS_DD_ID_ATTR_ID);
			tlv->attr_len = htonl(4);
			*(uint32_t *)tlv->attr_value = htonl(uid);
			payload_len += 8 + 4;
		}
		break;
	case CMD_NEWDDSN:
		pdu->func_id = ISNS_DDS_REG;
		switch (argc) {
		case 2:
			name = (char *)argv[1];
			len = strlen(name) + 1;
			len += 4 - (len % 4);
			/* FALLTHROUGH */
		case 1:
			uid = argv[0];
		}
		tlv = (isns_tlv_t *)payload;
		tlv->attr_id = htonl(ISNS_DD_SET_NAME_ATTR_ID);
		tlv->attr_len = htonl(len);
		if (len > 0) {
			strcpy((char *)tlv->attr_value, name);
		}
		payload_len += 8 + len;
		payload += 8 + len;
		if (uid > 0) {
			tlv = (isns_tlv_t *)payload;
			tlv->attr_id = htonl(ISNS_DD_SET_ID_ATTR_ID);
			tlv->attr_len = htonl(4);
			*(uint32_t *)tlv->attr_value = htonl(uid);
			payload_len += 8 + 4;
		}
		break;
	default:
		break;
	}

	pdu->payload_len = payload_len;

	dump_pdu1(pdu);

	conn.in_packet.pdu = pdu;
	conn.out_packet.pdu = NULL;
	conn.out_packet.sz = 0;

	if (packet_split_verify(&conn) == 0) {
		cache_lock(conn.lock);
		conn.handler(&conn);
		conn.ec = cache_unlock(conn.lock, conn.ec);
	}

	if (conn.out_packet.pdu != NULL) {
		pdu_update_code(conn.out_packet.pdu,
		    &conn.out_packet.pl, conn.ec);
		dump_pdu2(conn.out_packet.pdu);
		free(conn.out_packet.pdu);
	} else if (conn.ec != 0) {
		printf("operation failed[%d].\n", conn.ec);
	}
}

static void
del_dd_dds(
	int cmd_id,
	int uid
)
{
	uint32_t buff[256];
	isns_pdu_t *pdu = (isns_pdu_t *)buff;
	uint8_t *payload = &pdu->payload[0];
	uint16_t payload_len = 0;
	isns_tlv_t *tlv;

	uint32_t tag;

	conn_arg_t conn;

	if (uid == 0) {
		return;
	}

	pdu->version = ISNSP_VERSION;

	if (cmd_id == CMD_DELDD) {
		tag = ISNS_DD_ID_ATTR_ID;
		pdu->func_id = ISNS_DD_DEREG;
	} else {
		tag = ISNS_DD_SET_ID_ATTR_ID;
		pdu->func_id = ISNS_DDS_DEREG;
	}

	/* source attribute */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_ISCSI_NAME_ATTR_ID);
	tlv->attr_len = htonl(32);
	strcpy((char *)tlv->attr_value, "i am a control node.");
	payload_len += 8 + 32;
	payload += 8 + 32;

	/* key attributes */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(tag);
	tlv->attr_len = htonl(4);
	*(uint32_t *)tlv->attr_value = htonl(uid);
	payload_len += 8 + 4;
	payload += 8 + 4;

	/* delimiter */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_DELIMITER_ATTR_ID);
	tlv->attr_len = htonl(0);
	payload_len += 8 + 0;
	payload += 8 + 0;

	/* operating attributes */

	pdu->payload_len = payload_len;

	dump_pdu1(pdu);

	conn.in_packet.pdu = pdu;
	conn.out_packet.pdu = NULL;
	conn.out_packet.sz = 0;

	if (packet_split_verify(&conn) == 0) {
		cache_lock(conn.lock);
		conn.handler(&conn);
		conn.ec = cache_unlock(conn.lock, conn.ec);
	}

	if (conn.out_packet.pdu != NULL) {
		pdu_update_code(conn.out_packet.pdu,
		    &conn.out_packet.pl, conn.ec);
		dump_pdu2(conn.out_packet.pdu);
		free(conn.out_packet.pdu);
	} else if (conn.ec != 0) {
		printf("operation failed[%d].\n", conn.ec);
	}
}

static void
update_dds(
	int cmd_id,
	int uid
)
{
	uint32_t buff[256];
	isns_pdu_t *pdu = (isns_pdu_t *)buff;
	uint8_t *payload = &pdu->payload[0];
	uint16_t payload_len = 0;
	isns_tlv_t *tlv;

	conn_arg_t conn;

	if (uid == 0) {
		return;
	}

	pdu->version = ISNSP_VERSION;

	pdu->func_id = ISNS_DDS_REG;

	/* source attribute */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_ISCSI_NAME_ATTR_ID);
	tlv->attr_len = htonl(32);
	strcpy((char *)tlv->attr_value, "i am a control node.");
	payload_len += 8 + 32;
	payload += 8 + 32;

	/* key attributes */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_DD_SET_ID_ATTR_ID);
	tlv->attr_len = htonl(4);
	*(uint32_t *)tlv->attr_value = htonl(uid);
	payload_len += 8 + 4;
	payload += 8 + 4;

	/* delimiter */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_DELIMITER_ATTR_ID);
	tlv->attr_len = htonl(0);
	payload_len += 8 + 0;
	payload += 8 + 0;

	/* operating attributes */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_DD_SET_STATUS_ATTR_ID);
	tlv->attr_len = htonl(4);
	if (cmd_id == CMD_ENABLE) {
		*(uint32_t *)tlv->attr_value = htonl(1);
	} else {
		*(uint32_t *)tlv->attr_value = htonl(0);
	}
	payload_len += 8 + 4;

	pdu->payload_len = payload_len;

	dump_pdu1(pdu);

	conn.in_packet.pdu = pdu;
	conn.out_packet.pdu = NULL;
	conn.out_packet.sz = 0;

	if (packet_split_verify(&conn) == 0) {
		cache_lock(conn.lock);
		conn.handler(&conn);
		conn.ec = cache_unlock(conn.lock, conn.ec);
	}

	if (conn.out_packet.pdu != NULL) {
		pdu_update_code(conn.out_packet.pdu,
		    &conn.out_packet.pl, conn.ec);
		dump_pdu2(conn.out_packet.pdu);
		free(conn.out_packet.pdu);
	} else if (conn.ec != 0) {
		printf("operation failed[%d].\n", conn.ec);
	}
}

static void
update_member(
	int cmd_id,
	int *argv
)
{
	uint32_t buff[256];
	isns_pdu_t *pdu = (isns_pdu_t *)buff;
	uint8_t *payload = &pdu->payload[0];
	uint16_t payload_len = 0;
	isns_tlv_t *tlv;
	uint32_t key_tag, op_tag, op_len;

	uint32_t uid = argv[0];
	uint32_t m_id;
	char *m_name;

	conn_arg_t conn;

	if (uid == 0) {
		printf("operation failed.\n");
		return;
	}

	pdu->version = ISNSP_VERSION;

	switch (cmd_id) {
	case CMD_ADDDD:
	case CMD_ADDDDN:
		pdu->func_id = ISNS_DD_REG;
		break;
	case CMD_REMDD:
	case CMD_REMDDN:
		pdu->func_id = ISNS_DD_DEREG;
		break;
	case CMD_ADDDDSN:
		pdu->func_id = ISNS_DDS_REG;
		break;
	case CMD_REMDDSN:
		pdu->func_id = ISNS_DDS_DEREG;
		break;
	}
	switch (cmd_id) {
	case CMD_ADDDD:
	case CMD_REMDD:
		key_tag = ISNS_DD_ID_ATTR_ID;
		op_tag = ISNS_DD_ISCSI_NAME_ATTR_ID;
		m_name = (char *)argv[1];
		op_len = strlen(m_name);
		op_len += 4 - (op_len % 4);
		break;
	case CMD_ADDDDN:
	case CMD_REMDDN:
		key_tag = ISNS_DD_ID_ATTR_ID;
		op_tag = ISNS_DD_ISCSI_INDEX_ATTR_ID;
		m_id = argv[1];
		op_len = 4;
		break;
	case CMD_ADDDDSN:
	case CMD_REMDDSN:
		key_tag = ISNS_DD_SET_ID_ATTR_ID;
		op_tag = ISNS_DD_ID_ATTR_ID;
		m_id = argv[1];
		op_len = 4;
		break;
	}

	/* source attribute */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_ISCSI_NAME_ATTR_ID);
	tlv->attr_len = htonl(32);
	strcpy((char *)tlv->attr_value, "i am a control node.");
	payload_len += 8 + 32;
	payload += 8 + 32;

	/* key attributes */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(key_tag);
	tlv->attr_len = htonl(4);
	*(uint32_t *)tlv->attr_value = htonl(uid);
	payload_len += 8 + 4;
	payload += 8 + 4;

	/* delimiter */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(ISNS_DELIMITER_ATTR_ID);
	tlv->attr_len = htonl(0);
	payload_len += 8 + 0;
	payload += 8 + 0;

	/* operating attributes */
	tlv = (isns_tlv_t *)payload;
	tlv->attr_id = htonl(op_tag);
	tlv->attr_len = htonl(op_len);
	switch (cmd_id) {
	case CMD_ADDDD:
	case CMD_REMDD:
		strcpy((char *)tlv->attr_value, m_name);
		break;
	case CMD_ADDDDN:
	case CMD_ADDDDSN:
	case CMD_REMDDN:
	case CMD_REMDDSN:
		*(uint32_t *)tlv->attr_value = htonl(m_id);
		break;
	}
	payload_len += 8 + op_len;

	pdu->payload_len = payload_len;

	dump_pdu1(pdu);

	conn.in_packet.pdu = pdu;
	conn.out_packet.pdu = NULL;
	conn.out_packet.sz = 0;

	if (packet_split_verify(&conn) == 0) {
		cache_lock(conn.lock);
		conn.handler(&conn);
		conn.ec = cache_unlock(conn.lock, conn.ec);
	}

	if (conn.out_packet.pdu != NULL) {
		pdu_update_code(conn.out_packet.pdu,
		    &conn.out_packet.pl, conn.ec);
		dump_pdu2(conn.out_packet.pdu);
		free(conn.out_packet.pdu);
	} else if (conn.ec != 0) {
		printf("operation failed[%d].\n", conn.ec);
	}
}

static void
cmd_file(
	char *file
)
{
	char i = 0, ch, cmd[256];
	FILE *f = fopen(file, "r");
	if (f != NULL) {
		while ((ch = fgetc(f)) != 0 && ch != EOF) {
			if (ch == '\t') {
				cmd[i++] = ' ';
			} else if (ch != '\n') {
				cmd[i++] = ch;
			} else {
				cmd[i ++] = ' ';
				cmd[i] = 0;
				i = 0;
				printf("%s\n", cmd);
				if (run_cmd(cmd) != 0) {
					break;
				}
			}
		}
		fclose(f);
	} else {
		printf("Cannot open file %s.\n", file);
	}
}

static int
run_cmd(
	char *cmd
)
{
	int argc, argv[32];
	int cmd_id;
	cmd_id = getcmd(&argc, argv, cmd);
	switch (cmd_id) {
		case CMD_LIST:
			list_node();
			break;
		case CMD_LISTNE:
			list_entity();
			break;
		case CMD_LISTP:
			list_portal();
			break;
		case CMD_LISTPG:
			list_pg();
			break;
		case CMD_LISTDD:
			list_dd();
			break;
		case CMD_LISTDDS:
			list_dds();
			break;
		case CMD_LISTDDN:
			list_ddn(argv[0]);
			break;
		case CMD_LISTDDSN:
			list_ddsn(argv[0]);
			break;
		case CMD_NEWDD:
		case CMD_NEWDDS:
		case CMD_NEWDDN:
		case CMD_NEWDDSN:
			new_dd_dds(cmd_id, argc, argv);
			break;
		case CMD_DELDD:
		case CMD_DELDDS:
			del_dd_dds(cmd_id, argv[0]);
			break;
		case CMD_ENABLE:
		case CMD_DISABLE:
			update_dds(cmd_id, argv[0]);
			break;
		case CMD_ADDDD:
		case CMD_ADDDDN:
		case CMD_ADDDDSN:
		case CMD_REMDD:
		case CMD_REMDDN:
		case CMD_REMDDSN:
			update_member(cmd_id, argv);
			break;
		case CMD_PAUSE:
			printf("Press enter to continue...");
			getchar();
			break;
		case CMD_FILE:
			cmd_file((char *)argv[0]);
			break;
		case CMD_HELP:
			test_cli_help();
			break;
		case CMD_VERBOSE_MEMORY:
			verbose_mc = !verbose_mc;
			break;
		case CMD_VERBOSE_NET:
			verbose_net = !verbose_net;
			break;
		case CMD_VERBOSE_TIME:
			verbose_tc = !verbose_tc;
			break;
		case CMD_VERBOSE_LOCK:
			verbose_lock = !verbose_lock;
			break;
		case CMD_VERBOSE_PARSER:
			verbose_parser = !verbose_parser;
			break;
		case CMD_QUIT:
			/* clean up cli */
			/* notify sys control */
			shutdown_server();
			return (1);
		case CMD_NONE:
			break;
		default:
			printf("invalid command\n");
			break;
	}
	if (cmd_id != CMD_NONE) {
		printf("\n>");
	} else {
		printf(">");
	}
	return (0);
}

/*ARGSUSED*/
void *cli_test(void *arg) {
	char i = 0, ch, cmd[256];

	printf("iSNS Server test CLI.\n");
	printf("Copyright 2007 Sun Microsystems, Inc.\n");

	printf("\n>");
	while ((ch = getchar()) != 0 && ch != EOF) {
		if (ch == '\t') {
			cmd[i++] = ' ';
		} else if (ch != '\n') {
			cmd[i++] = ch;
		} else {
			cmd[i ++] = ' ';
			cmd[i] = 0;
			i = 0;
			if (run_cmd(cmd) != 0) {
				break;
			}
		}
	}

	return (NULL);
}
#endif
