/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <libndmp.h>
#include "ndmpadm.h"

/* static functions prototype */
static void ndmp_tprint_addr(char *, ndmp_ad_type_t, char *);
static void ndmp_print_env(ndmp_session_info_t *);
static void ndmp_connect_print_conn(ndmp_session_info_t *);
static void ndmp_connect_print_scsi_v2(ndmp_session_info_t *);
static void ndmp_connect_print_tape_v2(ndmp_session_info_t *);
static void ndmp_connect_print_mover_v2(ndmp_session_info_t *);
static void ndmp_connect_print_data_v2(ndmp_session_info_t *);
static void ndmp_connect_print_v2(int, ndmp_session_info_t *);
static void ndmp_connect_print_mover_v3(ndmp_session_info_t *);
static void ndmp_connect_print_data_v3(ndmp_session_info_t *);
static void ndmp_connect_print_v3(int, ndmp_session_info_t *);
static void ndmp_connection_print(int, ndmp_session_info_t *);

/* Boolean to string.  */
#define	B2S(b)	((b) ? "Yes" : "No")

/*
 * Print the address type and IP address if the address type is tcp
 */
static void
ndmp_tprint_addr(char *label, ndmp_ad_type_t addr_type, char *tcp_addr)
{
	if ((label == NULL) || (tcp_addr == NULL))
		return;

	switch (addr_type) {
	case NDMP_AD_LOCAL:
		(void) fprintf(stdout, gettext("\t%s type:\tLocal\n"), label);
		break;
	case NDMP_AD_TCP:
		(void) fprintf(stdout, gettext("\t%s type:\tTCP\n"), label);
		(void) fprintf(stdout, gettext("\t%s address:\t%s\n"),
		    label, tcp_addr);
		break;
	case NDMP_AD_FC:
		(void) fprintf(stdout, gettext("\t%s type:\tFC\n"), label);
		break;
	case NDMP_AD_IPC:
		(void) fprintf(stdout, gettext("\t%s type:\tIPC\n"), label);
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\t%s addr type unknown (0x%x)\n"),
		    label, addr_type);
	}
}

/*
 * Print all the data environment variables for the active session
 */
static void
ndmp_print_env(ndmp_session_info_t *si)
{
	int i, n;
	ndmp_dt_pval_t *ep;

	n = si->nsi_data.nd_env_len;
	ep = si->nsi_data.nd_env;
	for (i = 0; ep && i < n; i++, ep++) {
		(void) fprintf(stdout, gettext("\tdata.env[%d]:\t%s: "),
		    i, ep->np_name);
		if ((ep->np_value != NULL) && (*ep->np_value != NULL))
			(void) fprintf(stdout, "\"%s\"\n", ep->np_value);
	}
}

/*
 * Print common fields of the active connection.
 */
static void
ndmp_connect_print_conn(ndmp_session_info_t *si)
{
	(void) fprintf(stdout, gettext("\tSession Id:\t%d\n"), si->nsi_sid);
	(void) fprintf(stdout, gettext("\tProtocol version:\t%d\n"),
	    si->nsi_pver);
	(void) fprintf(stdout, gettext("\tAuthenticated:\t\t%s\n"),
	    B2S(si->nsi_auth));
	(void) fprintf(stdout, gettext("\tEOF:\t\t\t%s\n"), B2S(si->nsi_eof));
	if (si->nsi_cl_addr != NULL)
		(void) fprintf(stdout,
		    gettext("\tClient address:\t\t%s\n"), si->nsi_cl_addr);
}

/*
 * Print the connection SCSI info.
 */
static void
ndmp_connect_print_scsi_v2(ndmp_session_info_t *si)
{
	(void) fprintf(stdout, gettext("\tscsi.open:\t\t%s\n"),
	    B2S(si->nsi_scsi.ns_scsi_open != -1));
	if (si->nsi_scsi.ns_adapter_name)
		(void) fprintf(stdout, gettext("\tscsi.adapter:\t\t\"%s\"\n"),
		    si->nsi_scsi.ns_adapter_name);
	(void) fprintf(stdout, gettext("\tscsi.valid target:\t%s\n"),
	    B2S(si->nsi_scsi.ns_valid_target_set));
	if (si->nsi_scsi.ns_valid_target_set) {
		(void) fprintf(stdout,
		    gettext("\tscsi.SID:\t\t%d\n"), si->nsi_scsi.ns_scsi_id);
		(void) fprintf(stdout,
		    gettext("\tscsi.LUN:\t\t%d\n"), si->nsi_scsi.ns_lun);
	}
}

/*
 * Print the connection tape info.
 */
static void
ndmp_connect_print_tape_v2(ndmp_session_info_t *si)
{
	if (si->nsi_tape.nt_fd != -1) {
		(void) fprintf(stdout, gettext("\ttape.fd:\t\t%d\n"),
		    si->nsi_tape.nt_fd);
		(void) fprintf(stdout, gettext("\ttape.record count:\t%d\n"),
		    (int)si->nsi_tape.nt_rec_count);

		switch (si->nsi_tape.nt_mode) {
		case NDMP_TP_READ_MODE:
			(void) fprintf(stdout,
			    gettext("\ttape.mode:\t\tRead-only\n"));
			break;
		case NDMP_TP_WRITE_MODE:
			(void) fprintf(stdout,
			    gettext("\ttape.mode:\t\tRead/Write\n"));
			break;
		case NDMP_TP_RAW1_MODE:
			(void) fprintf(stdout,
			    gettext("\ttape.mode:\t\tRaw\n"));
			break;
		default:
			(void) fprintf(stdout,
			    gettext("\ttape.mode:\t\tUnknown (0x%x)\n"),
			    si->nsi_tape.nt_mode);
		}

		if (si->nsi_tape.nt_dev_name)
			(void) fprintf(stdout,
			    gettext("\ttape.device name:\t%s\n"),
			    si->nsi_tape.nt_dev_name);
		if (si->nsi_tape.nt_adapter_name)
			(void) fprintf(stdout,
			    gettext("\ttape.adapter name:\t\"%s\"\n"),
			    si->nsi_tape.nt_adapter_name);
		(void) fprintf(stdout,
		    gettext("\ttape.SID:\t\t%d\n"), si->nsi_tape.nt_sid);
		(void) fprintf(stdout,
		    gettext("\ttape.LUN:\t\t%d\n"), si->nsi_tape.nt_lun);
	} else
		(void) fprintf(stdout, gettext("\ttape.device:\t\tNot open\n"));
}

/*
 * Print the connection mover info.
 */
static void
ndmp_connect_print_mover_v2(ndmp_session_info_t *si)
{
	switch (si->nsi_mover.nm_state) {
	case NDMP_MV_STATE_IDLE:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tIdle\n"));
		break;
	case NDMP_MV_STATE_LISTEN:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tListen\n"));
		break;
	case NDMP_MV_STATE_ACTIVE:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tActive\n"));
		break;
	case NDMP_MV_STATE_PAUSED:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tPaused\n"));
		break;
	case NDMP_MV_STATE_HALTED:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tHalted\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.state:\t\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_state);
	}

	switch (si->nsi_mover.nm_mode) {
	case NDMP_MV_MODE_READ:
		(void) fprintf(stdout, gettext("\tmover.mode:\t\tRead\n"));
		break;
	case NDMP_MV_MODE_WRITE:
		(void) fprintf(stdout, gettext("\tmover.mode:\t\tWrite\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.mode:\t\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_mode);
	}

	switch (si->nsi_mover.nm_pause_reason) {
	case NDMP_MV_PAUSE_NA:
		(void) fprintf(stdout, gettext("\tmover.pause reason:\tN/A\n"));
		break;
	case NDMP_MV_PAUSE_EOM:
		(void) fprintf(stdout, gettext("\tmover.pause reason:\tEOM\n"));
		break;
	case NDMP_MV_PAUSE_EOF:
		(void) fprintf(stdout, gettext("\tmover.pause reason:\tEOF\n"));
		break;
	case NDMP_MV_PAUSE_SEEK:
		(void) fprintf(stdout,
		    gettext("\tmover.pause reason:\tSeek\n"));
		break;
	case NDMP_MV_PAUSE_MEDIA_ERROR:
		(void) fprintf(stdout,
		    gettext("\tmover.pause reason:\tMedia Error\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.pause reason:\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_pause_reason);
	}

	switch (si->nsi_mover.nm_halt_reason) {
	case NDMP_MV_HALT_NA:
		(void) fprintf(stdout, gettext("\tmover.halt reason:\tN/A\n"));
		break;
	case NDMP_MV_HALT_CONNECT_CLOSED:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tConnection closed\n"));
		break;
	case NDMP_MV_HALT_ABORTED:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tAborted\n"));
		break;
	case NDMP_MV_HALT_INTERNAL_ERROR:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tInternal error\n"));
		break;
	case NDMP_MV_HALT_CONNECT_ERROR:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tConnection error\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_halt_reason);
	}

	(void) fprintf(stdout, gettext("\tmover.record size:\t%d\n"),
	    (int)si->nsi_mover.nm_rec_size);
	(void) fprintf(stdout, gettext("\tmover.record number:\t%d\n"),
	    (int)si->nsi_mover.nm_rec_num);
	(void) fprintf(stdout, gettext("\tmover.pos:\t\t%lld\n"),
	    si->nsi_mover.nm_mov_pos);
	(void) fprintf(stdout, gettext("\tmover.win off:\t\t%lld\n"),
	    si->nsi_mover.nm_window_offset);
	(void) fprintf(stdout, gettext("\tmover.win len:\t\t%lld\n"),
	    si->nsi_mover.nm_window_length);
	(void) fprintf(stdout, gettext("\tmover.data socket:\t%d\n"),
	    si->nsi_mover.nm_sock);
}

/*
 * Print the connection data info.
 */
static void
ndmp_connect_print_data_v2(ndmp_session_info_t *si)
{
	int i;
	ndmp_dt_name_t *np;

	switch (si->nsi_data.nd_oper) {
	case NDMP_DT_OP_NOACTION:
		(void) fprintf(stdout, gettext("\tdata.operation:\t\tNone\n"));
		break;
	case NDMP_DT_OP_BACKUP:
		(void) fprintf(stdout,
		    gettext("\tdata.operation:\t\tBackup\n"));
		break;
	case NDMP_DT_OP_RECOVER:
		(void) fprintf(stdout,
		    gettext("\tdata.operation:\t\tRestore\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tdata.operation:\t\tUnknown (0x%x)\n"),
		    si->nsi_data.nd_oper);
	}

	switch (si->nsi_data.nd_state) {
	case NDMP_DT_STATE_IDLE:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tIdle\n"));
		break;
	case NDMP_DT_STATE_ACTIVE:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tActive\n"));
		break;
	case NDMP_DT_STATE_HALTED:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tHalted\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tdata.state:\t\tUnknown (0x%x)\n"),
		    si->nsi_data.nd_state);
	}

	switch (si->nsi_data.nd_halt_reason) {
	case NDMP_DT_HALT_NA:
		(void) fprintf(stdout, gettext("\tdata.halt reason:\tN/A\n"));
		break;
	case NDMP_DT_HALT_SUCCESSFUL:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tSuccessful\n"));
		break;
	case NDMP_DT_HALT_ABORTED:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tAborted\n"));
		break;
	case NDMP_DT_HALT_INTERNAL_ERROR:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tInternal error\n"));
		break;
	case NDMP_DT_HALT_CONNECT_ERROR:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tConnection error\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tUnknown (0x%x)\n"),
		    si->nsi_data.nd_halt_reason);
	}

	switch (si->nsi_data.nd_addr_type) {
	case NDMP_AD_LOCAL:
		(void) fprintf(stdout, gettext("\tdata.mover type:\tLocal\n"));
		break;
	case NDMP_AD_TCP:
		(void) fprintf(stdout, gettext("\tdata.mover type:\tTCP\n"));
		if (si->nsi_data.nd_tcp_addr)
			(void) fprintf(stdout,
			    gettext("\tdata.mover address:\t%s\n"),
			    si->nsi_data.nd_tcp_addr);
		(void) fprintf(stdout, gettext("\tdata.sock:\t%d\n"),
		    si->nsi_data.nd_sock);
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tdata.mover type:\tUnknown (0x%x)\n"),
		    si->nsi_data.nd_addr_type);
	}

	(void) fprintf(stdout, gettext("\tdata.aborted:\t\t%s\n"),
	    B2S(si->nsi_data.nd_abort));
	(void) fprintf(stdout, gettext("\tdata.read offset:\t%llu\n"),
	    si->nsi_data.nd_read_offset);
	(void) fprintf(stdout, gettext("\tdata.read length:\t%llu\n"),
	    si->nsi_data.nd_read_length);
	(void) fprintf(stdout, gettext("\tdata.total size:\t%llu\n"),
	    si->nsi_data.nd_total_size);

	ndmp_print_env(si);

	np = si->nsi_data.nd_nlist.nld_nlist;
	for (i = 0; np && i < (int)si->nsi_data.nld_nlist_len; i++, np++) {
		if ((np->nn_name) && (np->nn_dest)) {
			(void) fprintf(stdout,
			    gettext("\tdata.nlist[%d]:\tname: "
			    "\"%s\"\n\t\tdest:\"%s\"\n"),
			    i, np->nn_name, np->nn_dest);
		}
	}
}

/*
 * Print V2 connection info for the given category.
 */
static void
ndmp_connect_print_v2(int cat, ndmp_session_info_t *si)
{
		if (cat & NDMP_CAT_SCSI)
			ndmp_connect_print_scsi_v2(si);
		if (cat & NDMP_CAT_TAPE)
			ndmp_connect_print_tape_v2(si);
		if (cat & NDMP_CAT_MOVER)
			ndmp_connect_print_mover_v2(si);
		if (cat & NDMP_CAT_DATA)
			ndmp_connect_print_data_v2(si);
}

/*
 * Print the V3 connection mover info.
 */
static void
ndmp_connect_print_mover_v3(ndmp_session_info_t *si)
{
	switch (si->nsi_mover.nm_state) {
	case NDMP_MV_STATE_IDLE:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tIdle\n"));
		break;
	case NDMP_MV_STATE_LISTEN:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tListen\n"));
		break;
	case NDMP_MV_STATE_ACTIVE:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tActive\n"));
		break;
	case NDMP_MV_STATE_PAUSED:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tPaused\n"));
		break;
	case NDMP_MV_STATE_HALTED:
		(void) fprintf(stdout, gettext("\tmover.state:\t\tHalted\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.state:\t\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_state);
	}

	switch (si->nsi_mover.nm_mode) {
	case NDMP_MV_MODE_READ:
		(void) fprintf(stdout, gettext("\tmover.mode:\t\tRead\n"));
		break;
	case NDMP_MV_MODE_WRITE:
		(void) fprintf(stdout, gettext("\tmover.mode:\t\tWrite\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.mode:\t\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_mode);
	}

	switch (si->nsi_mover.nm_pause_reason) {
	case NDMP_MV_PAUSE_NA:
		(void) fprintf(stdout, gettext("\tmover.pause reason:\tN/A\n"));
		break;
	case NDMP_MV_PAUSE_EOM:
		(void) fprintf(stdout, gettext("\tmover.pause reason:\tEOM\n"));
		break;
	case NDMP_MV_PAUSE_EOF:
		(void) fprintf(stdout, gettext("\tmover.pause reason:\tEOF\n"));
		break;
	case NDMP_MV_PAUSE_SEEK:
		(void) fprintf(stdout,
		    gettext("\tmover.pause reason:\tSeek\n"));
		break;
	case NDMP_MV_PAUSE_MEDIA_ERROR:
		(void) fprintf(stdout,
		    gettext("\tmover.pause reason:\tMedia Error\n"));
		break;
	case NDMP_MV_PAUSE_EOW:
		(void) fprintf(stdout, gettext("\tmover.pause reason:\tEOW\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.pause reason:\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_pause_reason);
	}

	switch (si->nsi_mover.nm_halt_reason) {
	case NDMP_MV_HALT_NA:
		(void) fprintf(stdout, gettext("\tmover.halt reason:\tN/A\n"));
		break;
	case NDMP_MV_HALT_CONNECT_CLOSED:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tConnection closed\n"));
		break;
	case NDMP_MV_HALT_ABORTED:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tAborted\n"));
		break;
	case NDMP_MV_HALT_INTERNAL_ERROR:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tInternal error\n"));
		break;
	case NDMP_MV_HALT_CONNECT_ERROR:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tConnection error\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tmover.halt reason:\tUnknown (0x%x)\n"),
		    si->nsi_mover.nm_halt_reason);
	}

	(void) fprintf(stdout, gettext("\tmover.record size:\t%d\n"),
	    (int)si->nsi_mover.nm_rec_size);
	(void) fprintf(stdout, gettext("\tmover.record number:\t%d\n"),
	    (int)si->nsi_mover.nm_rec_num);
	(void) fprintf(stdout, gettext("\tmover.pos:\t\t%lld\n"),
	    si->nsi_mover.nm_mov_pos, si->nsi_mover.nm_mov_pos);

	(void) fprintf(stdout, gettext("\tmover.win len:\t\t%lld\n"),
	    si->nsi_mover.nm_window_length, si->nsi_mover.nm_window_length);

	(void) fprintf(stdout, gettext("\tmover.win off:\t\t%lld\n"),
	    si->nsi_mover.nm_window_offset);
	switch (si->nsi_mover.nm_state) {
	case NDMP_MV_STATE_IDLE:
		if (si->nsi_mover.nm_listen_sock != -1)
			(void) fprintf(stdout,
			    gettext("\tmover.listenSock:\t%d\n"),
			    si->nsi_mover.nm_listen_sock);
		if (si->nsi_mover.nm_sock != -1)
			(void) fprintf(stdout, gettext("\tmover.sock:\t%d\n"),
			    si->nsi_mover.nm_sock);
		break;
	case NDMP_MV_STATE_LISTEN:
		(void) fprintf(stdout, gettext("\tmover.listen socket:\t%d\n"),
		    si->nsi_mover.nm_listen_sock);
		ndmp_tprint_addr(gettext("mover.listen"),
		    si->nsi_mover.nm_addr_type, si->nsi_mover.nm_tcp_addr);
		break;
	case NDMP_MV_STATE_ACTIVE:
	case NDMP_MV_STATE_PAUSED:
	case NDMP_MV_STATE_HALTED:
		(void) fprintf(stdout, gettext("\tmover.data socket:\t%d\n"),
		    si->nsi_mover.nm_sock);
		ndmp_tprint_addr(gettext("mover.data connection"),
		    si->nsi_mover.nm_addr_type, si->nsi_mover.nm_tcp_addr);
		break;
	}
}

/*
 * Print the connection data info.
 */
static void
ndmp_connect_print_data_v3(ndmp_session_info_t *si)
{
	int i;
	ndmp_dt_name_v3_t *np;

	switch (si->nsi_data.nd_oper) {
	case NDMP_DT_OP_NOACTION:
		(void) fprintf(stdout, gettext("\tdata.operation:\t\tNone\n"));
		break;
	case NDMP_DT_OP_BACKUP:
		(void) fprintf(stdout,
		    gettext("\tdata.operation:\t\tBackup\n"));
		break;
	case NDMP_DT_OP_RECOVER:
		(void) fprintf(stdout,
		    gettext("\tdata.operation:\t\tRestore\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tdata.operation:\t\tUnknown (0x%x)\n"),
		    si->nsi_data.nd_oper);
	}

	switch (si->nsi_data.nd_state) {
	case NDMP_DT_STATE_IDLE:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tIdle\n"));
		break;
	case NDMP_DT_STATE_ACTIVE:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tActive\n"));
		break;
	case NDMP_DT_STATE_HALTED:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tHalted\n"));
		break;
	case NDMP_DT_STATE_LISTEN:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tListen\n"));
		break;
	case NDMP_DT_STATE_CONNECTED:
		(void) fprintf(stdout, gettext("\tdata.state:\t\tConnected\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tdata.state:\t\tUnknown (0x%x)\n"),
		    si->nsi_data.nd_state);
	}

	switch (si->nsi_data.nd_halt_reason) {
	case NDMP_DT_HALT_NA:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tN/A\n"));
		break;
	case NDMP_DT_HALT_SUCCESSFUL:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tSuccessful\n"));
		break;
	case NDMP_DT_HALT_ABORTED:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tAborted\n"));
		break;
	case NDMP_DT_HALT_INTERNAL_ERROR:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tInternal error\n"));
		break;
	case NDMP_DT_HALT_CONNECT_ERROR:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tConnection error\n"));
		break;
	default:
		(void) fprintf(stdout,
		    gettext("\tdata.halt reason:\tUnknown (0x%x)\n"),
		    si->nsi_data.nd_halt_reason);
	}

	switch (si->nsi_data.nd_state) {
	case NDMP_DT_STATE_IDLE:
		if (si->nsi_data.nd_sock != -1)
			(void) fprintf(stdout,
			    gettext("\tdata.data socket:\t%d\n"),
			    si->nsi_data.nd_sock);
		if (si->nsi_data.nd_nlist.nld_dt_v3.dv3_listen_sock != -1)
			(void) fprintf(stdout,
			    gettext("\tdata.data socket:\t%d\n"),
			    si->nsi_data.nd_nlist.nld_dt_v3.dv3_listen_sock);
		break;
	case NDMP_DT_STATE_LISTEN:
		(void) fprintf(stdout, gettext("\tdata.listen socket:\t%d\n"),
		    si->nsi_data.nd_nlist.nld_dt_v3.dv3_listen_sock);
		ndmp_tprint_addr(gettext("data.listen"),
		    si->nsi_data.nd_addr_type, si->nsi_data.nd_tcp_addr);
		break;
	case NDMP_DT_STATE_ACTIVE:
	case NDMP_DT_STATE_HALTED:
	case NDMP_DT_STATE_CONNECTED:
		(void) fprintf(stdout, gettext("\tdata.data socket:\t%d\n"),
		    si->nsi_data.nd_sock);
		ndmp_tprint_addr(gettext("data.data"),
		    si->nsi_data.nd_addr_type, si->nsi_data.nd_tcp_addr);
		break;
	}

	(void) fprintf(stdout, gettext("\tdata.aborted:\t\t%s\n"),
	    B2S(si->nsi_data.nd_abort));
	(void) fprintf(stdout, gettext("\tdata.read offset:\t%llu\n"),
	    si->nsi_data.nd_read_offset);
	(void) fprintf(stdout, gettext("\tdata.read length:\t%llu\n"),
	    si->nsi_data.nd_read_length);
	(void) fprintf(stdout, gettext("\tdata.total size:\t%llu\n"),
	    si->nsi_data.nd_total_size);
	(void) fprintf(stdout,
	    gettext("\tdata.bytes processed:\t%lld\n"),
	    si->nsi_data.nd_nlist.nld_dt_v3.dv3_bytes_processed);

	ndmp_print_env(si);

	np = si->nsi_data.nd_nlist.nld_dt_v3.dv3_nlist;
	for (i = 0; np && i < si->nsi_data.nld_nlist_len; i++, np++) {
		(void) fprintf(stdout, gettext("\tdata.nlist[%d]:\tname:\n"),
		    i);
		if (np->nn3_opath)
			(void) fprintf(stdout,
			    gettext("\t\torig: \"%s\"\n"), np->nn3_opath);
		if (np->nn3_dpath)
			(void) fprintf(stdout,
			    gettext("\t\tdest: \"%s\"\n"), np->nn3_dpath);
		else
			(void) fprintf(stdout, gettext("\t\tdest:\n"));
		(void) fprintf(stdout,
		    gettext("\t\tnode: %lld\n"), np->nn3_node);
		(void) fprintf(stdout, gettext("\t\tfh_info: %lld\n"),
		    np->nn3_fh_info);
	}
}

/*
 * Print V3 connection info for given category.
 */
static void
ndmp_connect_print_v3(int cat, ndmp_session_info_t *si)
{
	if (cat & NDMP_CAT_SCSI)
		ndmp_connect_print_scsi_v2(si);
	if (cat & NDMP_CAT_TAPE)
		ndmp_connect_print_tape_v2(si);
	if (cat & NDMP_CAT_MOVER)
		ndmp_connect_print_mover_v3(si);
	if (cat & NDMP_CAT_DATA)
		ndmp_connect_print_data_v3(si);
}

/*
 * Print the list of all active sessions to the clients.  For each version,
 * call the appropriate print function.
 */
static void
ndmp_connection_print(int cat, ndmp_session_info_t *si)
{
	switch (si->nsi_pver) {
	case NDMP_V2:
		ndmp_connect_print_conn(si);
		ndmp_connect_print_v2(cat, si);
		break;
	case NDMP_V3:
	case NDMP_V4:
		ndmp_connect_print_conn(si);
		ndmp_connect_print_v3(cat, si);
		break;
	default:
		(void) fprintf(stdout,
		    gettext("Invalid version %d"), si->nsi_pver);
	}
}

/*
 * Print the list of all active sessions to the clients.
 */
void
ndmp_session_all_print(int cat, ndmp_session_info_t *si, size_t num)
{
	int i;
	ndmp_session_info_t *sp;

	sp = si;
	for (i = 0; i < num; i++, sp++) {
		ndmp_connection_print(cat, sp);
		(void) fprintf(stdout, "\n");
	}

	if (num == 0) {
		(void) fprintf(stdout, gettext("No active session.\n"));
	} else {
		(void) fprintf(stdout, gettext("%d active sessions.\n"), num);
	}
}

/*
 * Print the connection information for the given category.
 */
void
ndmp_session_print(int cat,  ndmp_session_info_t *si)
{
	ndmp_connection_print(cat, si);
}

void
ndmp_devinfo_print(ndmp_devinfo_t *dip, size_t size)
{
	int i;

	if (dip == NULL) {
		(void) fprintf(stdout, gettext("No device attached.\n"));
		return;
	}

	for (i = 0; i < size; i++, dip++) {
		/*
		 * Don't print dead links.
		 */
		if ((access(dip->nd_name, F_OK) == -1) && (errno == ENOENT))
			continue;
		switch (dip->nd_dev_type) {
		case NDMP_SINQ_TAPE_ROBOT:
			(void) fprintf(stdout, gettext("Robot (Changer):\n"));
			break;
		case NDMP_SINQ_SEQ_ACCESS_DEVICE:
			(void) fprintf(stdout, gettext("Tape drive(s):\n"));
			break;
		}
		if (dip->nd_name)
			(void) fprintf(stdout,
			    gettext("\tName      : %s\n"), dip->nd_name);
		(void) fprintf(stdout,
		    gettext("\tLUN #     : %d\n"), dip->nd_lun);
		(void) fprintf(stdout,
		    gettext("\tSCSI ID # : %d\n"), dip->nd_sid);
		if (dip->nd_vendor)
			(void) fprintf(stdout,
			    gettext("\tVendor    : %s\n"), dip->nd_vendor);
		if (dip->nd_product)
			(void) fprintf(stdout,
			    gettext("\tProduct   : %s\n"), dip->nd_product);
		if (dip->nd_revision)
			(void) fprintf(stdout,
			    gettext("\tRevision  : %s\n"), dip->nd_revision);
		if (dip->nd_serial)
			(void) fprintf(stdout,
			    gettext("\tSerial    : %s\n"), dip->nd_serial);
		if (dip->nd_wwn)
			(void) fprintf(stdout,
			    gettext("\tWWN       : %s\n"), dip->nd_wwn);
		(void) fprintf(stdout, "\n");
	}
}
