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

#pragma D depends_on library ip.d
#pragma D depends_on library net.d	/* conninfo_t */
#pragma D depends_on library scsi.d	/* scsicmd_t and iscsiinfo_t */
#pragma D depends_on module genunix
#pragma D depends_on module iscsit
#pragma D depends_on module idm

#pragma D binding "1.5" translator
translator conninfo_t < idm_conn_t *P > {
	ci_local = (P->ic_laddr.ss_family == AF_INET) ?
	    inet_ntoa((ipaddr_t *)
	    &((struct sockaddr_in *)&P->ic_laddr)->sin_addr) :
	    inet_ntoa6(&((struct sockaddr_in6 *)&P->ic_laddr)->sin6_addr);

	ci_remote = (P->ic_raddr.ss_family == AF_INET) ?
	    inet_ntoa((ipaddr_t *)
	    &((struct sockaddr_in *)&P->ic_raddr)->sin_addr) :
	    inet_ntoa6(&((struct sockaddr_in6 *)&P->ic_raddr)->sin6_addr);

	ci_protocol = (P->ic_laddr.ss_family == AF_INET) ? "ipv4" : "ipv6";
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_async_evt_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = (((uint64_t)P->lun[0] << (64 - 0*8 - 8)) +
            ((uint64_t)P->lun[1] << (64 - 1*8 - 8)) +
            ((uint64_t)P->lun[2] << (64 - 2*8 - 8)) +
            ((uint64_t)P->lun[3] << (64 - 3*8 - 8)) +
            ((uint64_t)P->lun[4] << (64 - 4*8 - 8)) +
            ((uint64_t)P->lun[5] << (64 - 5*8 - 8)) +
            ((uint64_t)P->lun[6] << (64 - 6*8 - 8)) +
            ((uint64_t)P->lun[7] << (64 - 7*8 - 8)));
	ii_itt = 0;
	ii_ttt = 0;
	ii_cmdsn = 0;
	ii_statsn = ntohl(P->statsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_login_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = 0xffffffff;
	ii_cmdsn = ntohl(P->cmdsn);
	ii_statsn = ntohl(P->expstatsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_login_rsp_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = 0xffffffff;
	ii_cmdsn = ntohl(P->expcmdsn);
	ii_statsn = ntohl(P->statsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_logout_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = 0xffffffff;
	ii_cmdsn = ntohl(P->cmdsn);
	ii_statsn = ntohl(P->expstatsn);
	ii_datasn = 0;
	ii_datalen = 0;
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_logout_rsp_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = 0xffffffff;
	ii_cmdsn = 0;
	ii_statsn = ntohl(P->statsn);
	ii_datasn = 0;
	ii_datalen = 0;
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_rtt_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->ttt);
	ii_cmdsn = ntohl(P->expcmdsn);
	ii_statsn = ntohl(P->statsn);
	ii_datasn = ntohl(P->rttsn);
	ii_datalen = 0;
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_data_rsp_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = (((uint64_t)P->lun[0] << (64 - 0*8 - 8)) +
	    ((uint64_t)P->lun[1] << (64 - 1*8 - 8)) +
            ((uint64_t)P->lun[2] << (64 - 2*8 - 8)) +
            ((uint64_t)P->lun[3] << (64 - 3*8 - 8)) +
            ((uint64_t)P->lun[4] << (64 - 4*8 - 8)) +
            ((uint64_t)P->lun[5] << (64 - 5*8 - 8)) +
            ((uint64_t)P->lun[6] << (64 - 6*8 - 8)) +
            ((uint64_t)P->lun[7] << (64 - 7*8 - 8)));
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->ttt);
	ii_cmdsn = ntohl(P->expcmdsn);
	ii_statsn = ntohl(P->statsn);
	ii_datasn = ntohl(P->datasn);
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_data_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = (((uint64_t)P->lun[0] << (64 - 0*8 - 8)) +
            ((uint64_t)P->lun[1] << (64 - 1*8 - 8)) +
            ((uint64_t)P->lun[2] << (64 - 2*8 - 8)) +
            ((uint64_t)P->lun[3] << (64 - 3*8 - 8)) +
            ((uint64_t)P->lun[4] << (64 - 4*8 - 8)) +
            ((uint64_t)P->lun[5] << (64 - 5*8 - 8)) +
            ((uint64_t)P->lun[6] << (64 - 6*8 - 8)) +
            ((uint64_t)P->lun[7] << (64 - 7*8 - 8)));
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->ttt);
	ii_cmdsn = 0;
	ii_statsn = ntohl(P->expstatsn);
	ii_datasn = ntohl(P->datasn);
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_nop_in_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = (((uint64_t)P->lun[0] << (64 - 0*8 - 8)) +
            ((uint64_t)P->lun[1] << (64 - 1*8 - 8)) +
            ((uint64_t)P->lun[2] << (64 - 2*8 - 8)) +
            ((uint64_t)P->lun[3] << (64 - 3*8 - 8)) +
            ((uint64_t)P->lun[4] << (64 - 4*8 - 8)) +
            ((uint64_t)P->lun[5] << (64 - 5*8 - 8)) +
            ((uint64_t)P->lun[6] << (64 - 6*8 - 8)) +
            ((uint64_t)P->lun[7] << (64 - 7*8 - 8)));
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->ttt);
	ii_cmdsn = ntohl(P->expcmdsn);
	ii_statsn = ntohl(P->statsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_nop_out_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = (((uint64_t)P->lun[0] << (64 - 0*8 - 8)) +
            ((uint64_t)P->lun[1] << (64 - 1*8 - 8)) +
            ((uint64_t)P->lun[2] << (64 - 2*8 - 8)) +
            ((uint64_t)P->lun[3] << (64 - 3*8 - 8)) +
            ((uint64_t)P->lun[4] << (64 - 4*8 - 8)) +
            ((uint64_t)P->lun[5] << (64 - 5*8 - 8)) +
            ((uint64_t)P->lun[6] << (64 - 6*8 - 8)) +
            ((uint64_t)P->lun[7] << (64 - 7*8 - 8)));
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->ttt);
	ii_cmdsn = ntohl(P->cmdsn);
	ii_statsn = ntohl(P->expstatsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_scsi_cmd_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = (((uint64_t)P->lun[0] << (64 - 0*8 - 8)) +
            ((uint64_t)P->lun[1] << (64 - 1*8 - 8)) +
            ((uint64_t)P->lun[2] << (64 - 2*8 - 8)) +
            ((uint64_t)P->lun[3] << (64 - 3*8 - 8)) +
            ((uint64_t)P->lun[4] << (64 - 4*8 - 8)) +
            ((uint64_t)P->lun[5] << (64 - 5*8 - 8)) +
            ((uint64_t)P->lun[6] << (64 - 6*8 - 8)) +
            ((uint64_t)P->lun[7] << (64 - 7*8 - 8)));
	ii_itt = ntohl(P->itt);
	ii_ttt = 0xffffffff;
	ii_cmdsn = ntohl(P->cmdsn);
	ii_statsn = ntohl(P->expstatsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_scsi_rsp_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = 0xffffffff;
	ii_cmdsn = ntohl(P->expcmdsn);
	ii_statsn = ntohl(P->statsn);
	ii_datasn = ntohl(P->expdatasn);
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_scsi_task_mgt_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = (((uint64_t)P->lun[0] << (64 - 0*8 - 8)) +
            ((uint64_t)P->lun[1] << (64 - 1*8 - 8)) +
            ((uint64_t)P->lun[2] << (64 - 2*8 - 8)) +
            ((uint64_t)P->lun[3] << (64 - 3*8 - 8)) +
            ((uint64_t)P->lun[4] << (64 - 4*8 - 8)) +
            ((uint64_t)P->lun[5] << (64 - 5*8 - 8)) +
            ((uint64_t)P->lun[6] << (64 - 6*8 - 8)) +
            ((uint64_t)P->lun[7] << (64 - 7*8 - 8)));
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->rtt); 
	ii_cmdsn = ntohl(P->cmdsn);
	ii_statsn = ntohl(P->expstatsn);
	ii_datasn = 0;
	ii_datalen = 0;
	ii_flags = 0;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_scsi_task_mgt_rsp_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->rtt);
	ii_cmdsn = ntohl(P->expcmdsn);
	ii_statsn = ntohl(P->statsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_text_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->ttt);
	ii_cmdsn = ntohl(P->cmdsn);
	ii_statsn = ntohl(P->expstatsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < iscsi_text_rsp_hdr_t *P > {
	ii_initiator = ((idm_conn_t *)arg0)->ic_initiator_name;
	ii_target = ((idm_conn_t *)arg0)->ic_target_name;
	ii_isid = ((idm_conn_t *)arg0)->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (((idm_conn_t *)arg0)->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0; /* NA */
	ii_itt = ntohl(P->itt);
	ii_ttt = ntohl(P->ttt);
	ii_cmdsn = ntohl(P->expcmdsn);
	ii_statsn = ntohl(P->statsn);
	ii_datasn = 0;
	ii_datalen = P->dlength[0] << 16 | P->dlength[1] << 8 | P->dlength[2];
	ii_flags = P->flags;
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < idm_conn_t *P > {
	ii_initiator = P->ic_initiator_name;
	ii_target = P->ic_target_name;
	ii_isid = P->ic_isid;
	ii_tsih = ((idm_conn_t *)arg0)->ic_tsih;
	ii_transport = (P->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_ISER) ? "iser-ib" :
	    (P->ic_transport_type ==
	    IDM_TRANSPORT_TYPE_SOCKETS) ? "sockets" : "Unknown";
	ii_lun = 0;
	ii_itt = 0;
	ii_ttt = 0;
	ii_cmdsn = 0;
	ii_statsn = 0;
	ii_datasn = 0;
	ii_datalen = 0;
	ii_flags = 0;
};

#pragma D binding "1.5" translator
translator xferinfo_t < uintptr_t P > {
	xfer_laddr = (arg1 == NULL) ? 0xffffffff : (uintptr_t)arg1;
	xfer_loffset = arg2;
	xfer_lkey = 0; /* not used */
	xfer_len = arg6;
	xfer_raddr = arg3;
	xfer_roffset = arg4;
	xfer_rkey = arg5;
	xfer_type = arg7;
};

inline int IDM_TRANSPORT_TYPE_ISER = 0;
#pragma D binding "1.5" IDM_TRANSPORT_TYPE_ISER
inline int IDM_TRANSPORT_TYPE_SOCKETS = 1;
#pragma D binding "1.5" IDM_TRANSPORT_TYPE_SOCKETS

