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

#pragma	D depends_on library net.d
#pragma	D depends_on library scsi.d
#pragma	D depends_on module genunix
#pragma	D depends_on module fct

/*
 * FC port information.
 */
typedef struct fc_port_info {
	string fcp_node_wwn;		/* node WWN */
	string fcp_sym_node_name;	/* node symbolic name */
	string fcp_sym_port_name;	/* port symbolic name */
	uint32_t fcp_port_hard_address;	/* port hard address */
} fc_port_info_t;

/*
 * FC transfer info (somewhat analogous to iscsiinfo_t)
 * Represents data transfer details.
 */
typedef struct fc_xferinfo {
	uint32_t fcx_len;
	uint32_t fcx_offset;
	uint16_t fcx_flags;	/* db_flags as defined in sys/stmf.h */
} fc_xferinfo_t;

/*
 * conninfo translators
 */

/*
 * Translator for conninfo, translating from the local port.
 */
#pragma D binding "1.5" translator
translator conninfo_t < fct_local_port_t *P > {
 	ci_local = P->port_pwwn_str[0] ?
	    P->port_pwwn_str : "<unknown>";
 	ci_remote = "<unknown>";
	ci_protocol = "fc";
};

/*
 * Translator for conninfo, translating from the local port implementation.
 */
#pragma D binding "1.5" translator
translator conninfo_t < fct_i_local_port_t *P > {
 	ci_local = P->iport_port->port_pwwn_str[0] ?
		 P->iport_port->port_pwwn_str : "<unknown>";
 	ci_remote = "<unknown>";
	ci_protocol = "fc";
};

/*
 * Translator for conninfo, translating from fct cmd struct.
 */
#pragma D binding "1.5" translator
translator conninfo_t < fct_cmd_t *C > {
 	ci_local = (C->cmd_port ?
		 (C->cmd_port->port_pwwn_str[0] ?
		  C->cmd_port->port_pwwn_str : "<unknown>") :
		 "<unknown>");

 	ci_remote = (C->cmd_rp ?
		 (C->cmd_rp->rp_pwwn_str[0] ?
		  C->cmd_rp->rp_pwwn_str : "<unknown>") :
		 "<unknown>");

	ci_protocol = "fc";
};


/*
 * fc_port_info_t translators.
 */

/*
 * Translator for fc_port_info_t, translating from the local port.
 */
#pragma D binding "1.5" translator
translator fc_port_info_t < fct_local_port_t *P > {
        /* node WWN */
	fcp_node_wwn = P->port_nwwn_str[0] ?
		     P->port_nwwn_str : "<unknown>";

	/* node symbolic name */
	fcp_sym_node_name = P->port_sym_node_name ? 
		P->port_sym_node_name : `utsname.nodename;

	/* port symbolic name */
	fcp_sym_port_name = P->port_sym_port_name ?
			P->port_sym_port_name : "<unknown>";

	/* port hard address */
	fcp_port_hard_address = P->port_hard_address;
};


/*
 * Translator for fc_port_info_t, translating from the local port impl.
 */
#pragma D binding "1.5" translator
translator fc_port_info_t < fct_i_local_port_t *P > {
        /* node WWN */

	fcp_node_wwn = (P->iport_port ?
			   (P->iport_port->port_nwwn_str[0] ?
		               P->iport_port->port_nwwn_str :
			       "<unknown>") : 
		           "<bad iport_port ptr>");

	fcp_sym_node_name = 
			 (P->iport_port ?
			   (P->iport_port->port_sym_node_name ?
		            P->iport_port->port_sym_node_name : "<unknown>") : 
		           "<bad iport_port ptr>");

	fcp_sym_port_name =
			 (P->iport_port ?
			   (P->iport_port->port_sym_port_name ?
		            P->iport_port->port_sym_port_name : "<unknown>") : 
		           "<bad iport_port ptr>");

	fcp_port_hard_address = 
			 (P->iport_port ?
			   P->iport_port->port_hard_address : 0);
};

/*
 * Translator for fc_port_info, translating from the remote port impl
 */
#pragma D binding "1.5" translator
translator fc_port_info_t < fct_i_remote_port_t *P > {

        /* node WWN */
	fcp_node_wwn = P->irp_rp ?
			   (P->irp_rp->rp_nwwn_str[0] ?
			     P->irp_rp->rp_nwwn_str : "<unknown>") :
                           "<unknown>";

	/* node symbolic name */
	fcp_sym_node_name = P->irp_snn ? P->irp_snn : "<unknown>";

	/* port symbolic name */
	fcp_sym_port_name = P->irp_spn ? P->irp_spn : "<unknown>";

	/* port hard address */
	fcp_port_hard_address = P->irp_rp ? P->irp_rp->rp_id : 0;
};

/*
 * Translator for fc_xferinfo, translating from stmf_data_buf_t.
 */
#pragma D binding "1.5" translator
translator fc_xferinfo_t < stmf_data_buf_t *B > {
	   fcx_len = B->db_data_size;
	   fcx_offset = B->db_relative_offset;
	   fcx_flags = B->db_flags;
};
