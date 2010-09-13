;
; Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
; Use is subject to license terms.
;
; CDDL HEADER START
;
; The contents of this file are subject to the terms of the
; Common Development and Distribution License, Version 1.0 only
; (the "License").  You may not use this file except in compliance
; with the License.
;
; You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
; or http://www.opensolaris.org/os/licensing.
; See the License for the specific language governing permissions
; and limitations under the License.
;
; When distributing Covered Code, include this CDDL HEADER in each
; file and include the License file at usr/src/OPENSOLARIS.LICENSE.
; If applicable, add the following below this CDDL HEADER, with the
; fields enclosed by brackets "[]" replaced with your own identifying
; information: Portions Copyright [yyyy] [name of copyright owner]
;
; CDDL HEADER END
;
;       Multi-threaded general purpose script for the
;	Symbios 53C825/875 host bus adapter chips.
;
; ident	"%Z%%M%	%I%	%E% SMI"

	ARCH 825A

	ABSOLUTE NBIT_ICON = 0x10	; CON bit in SCNTL1 register

;
; Scatter/Gather DMA instructions for datain and dataout
;
	ENTRY	dt_do_list_end
	ENTRY	dt_di_list_end
	ENTRY	do_list_end
	ENTRY	di_list_end

;       SCSI I/O entry points.  One of these addresses must be loaded into the
;       DSA register to initiate SCSI I/O.

	ENTRY start_up
	ENTRY resel_m
	ENTRY ext_msg_out
	ENTRY clear_ack
	ENTRY continue
	ENTRY errmsg
	ENTRY abort
	ENTRY dev_reset
	ENTRY ext_msg_in
	ENTRY phase_mis_match

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

start_up:
	SELECT ATN FROM 0, REL(resel_m)

; after selection, next phase should be msg_out or status
	INT PASS(NINT_ILI_PHASE), WHEN NOT MSG_OUT

msgout:
	MOVE FROM PASS(NTOFFSET(nt_sendmsg)), WHEN MSG_OUT
	JUMP REL(command_phase), WHEN CMD
	JUMP REL(switch), WHEN NOT MSG_OUT
; target requested repeat, set atn in case it's an extended msg
	SET ATN
	JUMP REL(msgout)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; The sync (SDTR) message interrupt handler restarts here if the
; initiator and target have both succesfully exchanged SDTR messages.

clear_ack:
	CLEAR ACK
	JUMP REL(switch)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Restart here after phase mismatch interrupt, clear ATN in case the
; interrupt occurred during the msg_out phase.

continue:
	CLEAR ATN
	JUMP REL(switch)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Send error message to the target. Usually the target will change
; phase immediately. But if in data in or data out phase, or part
; way through a command or message in the phase change will happen
; at the end of the current phase.

errmsg:
	SET ATN
	CLEAR ACK
	JUMP REL(errmsg_out), WHEN MSG_OUT
; not message out phase, the target will change phase later
	JUMP REL(switch)

errmsg_out:
	MOVE FROM PASS(NTOFFSET(nt_errmsg)), WHEN MSG_OUT
	JUMP REL(switch) , WHEN NOT MSG_OUT
; target requested repeat
	JUMP REL(errmsg_out)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Send an abort message to a target that's attempting an invalid
; reconnection.

abort:
	SET ATN
	CLEAR ACK
	INT PASS(NINT_ILI_PHASE), WHEN NOT MSG_OUT

abort_out:
	MOVE FROM PASS(NTOFFSET(nt_errmsg)), WHEN MSG_OUT
	JUMP REL(abort_done), WHEN NOT MSG_OUT
	SET ATN
	JUMP REL(abort_out)

abort_done:
	MOVE 0x00 TO SCNTL2
	CLEAR ACK
	WAIT DISCONNECT
	INT PASS(NINT_OK)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; send an Abort or Bus Device Reset message and wait for the disconnect

dev_reset:
	MOVE 0x00 TO SCNTL2
	SELECT ATN FROM 0, REL(resel_m)
; after selection, next phase should be msg_out
	INT PASS(NINT_ILI_PHASE), WHEN NOT MSG_OUT

dev_reset_out:
	MOVE FROM PASS(NTOFFSET(nt_sendmsg)), WHEN MSG_OUT
	CLEAR ACK
	MOVE SCNTL2 & 0x7F TO SCNTL2
	WAIT DISCONNECT
	INT PASS(NINT_DEV_RESET)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; The sync (SDTR) or wide (WDTR) message interrupt handler restarts here
; if the initiator needs to send an SDTR/WDTR message in response to the
; target's SDTR/WDTR.
;
; Set the ATN signal to let target know we've got a message to send
; and ack the last byte of its SDTR/WDTR message.

ext_msg_out:
	SET ATN
	CLEAR ACK
	JUMP REL(msg_out), WHEN MSG_OUT
; not message out phase, assume target decided not to do sync i/o
; if this doesn't work, change it to treat this as illegal phase
	CLEAR ATN
	INT PASS(NINT_NEG_REJECT)

msg_out:
	MOVE FROM PASS(NTOFFSET(nt_sendmsg)), WHEN MSG_OUT
	JUMP REL(ext_msg_out_chk), WHEN NOT MSG_OUT
	SET ATN				 ; target requested repeat
	JUMP REL(msg_out)


ext_msg_out_chk:
; test whether the target accepted the SDTR message
; any phase besides MSG_IN means the sdtr message is okay
	JUMP REL(switch), WHEN NOT MSG_IN

; any message besides Message Reject means the SDTR message is okay
	MOVE FROM PASS(NTOFFSET(nt_rcvmsg)), WHEN MSG_IN
	JUMP REL(msgin2), IF NOT 0x07		; anything else is okay

; SDTR got Message Reject response
	MOVE 0x00 TO SXFER
	INT PASS(NINT_NEG_REJECT)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

resel_m:
	WAIT RESELECT REL(alt_sig_p)
	MOVE SSID SHL SFBR
	MOVE SFBR SHL SFBR
	MOVE SFBR & 0x3C TO DSA0
	MOVE SCRATCHB1 TO SFBR
	MOVE SFBR TO DSA1
	MOVE SCRATCHB2 TO SFBR
	MOVE SFBR TO DSA2
	MOVE SCRATCHB3 TO SFBR
	MOVE SFBR TO DSA3
	SELECT FROM 0x00, REL(Next_Inst)
Next_Inst:
	MOVE 0x00 TO DSA0
	INT PASS(NINT_MSGIN), WHEN NOT MSG_IN
	;
	; reselection Identify msg.
	;
	MOVE FROM PASS(HBAOFFSET(g_rcvmsg)), WHEN MSG_IN
	CLEAR ACK
	;
	; Target will either continue in msg-in phase (tag q'ing) or
	; transistion to data or status phase.
	;
	; non-tq case: target switched to status phase.
	;
	INT PASS(NINT_RESEL), WHEN NOT MSG_IN	; Let UNIX driver grab it
	;
	; should be the 0x20 (tag msg).
	;
	MOVE FROM PASS(HBAOFFSET(g_moremsgin)), WHEN MSG_IN
	;
	; if the target resel and disconnects, handle that here.
	JUMP REL(resel_disc), IF 0x04
	;
	; Check msg-in byte for 20, 21, or 22.
	JUMP REL(Got_tag), IF 0x20 AND MASK 0x01
	INT PASS(NINT_RESEL), IF NOT 0x22	; Let UNIX driver grab it
Got_tag:
	CLEAR ACK
	MOVE FROM PASS(HBAOFFSET(g_tagmsg)), WHEN MSG_IN
	CLEAR ACK
	INT PASS(NINT_RESEL)			; Let UNIX driver grab it

alt_sig_p:
	; The driver hit sig_p to start a new cmd.
	; Test the connected bit in SCNTL1.  If its set, retry the
	; wait reselect.  Otherwise, let the driver start a new cmd.
	MOVE CTEST2 TO SFBR			; clear sig_p bit, if set
	MOVE SCNTL1 & NBIT_ICON TO SFBR		; test the connected bit

	; Interrupt if not connected.
	INT PASS(NINT_SIGPROC), IF NOT NBIT_ICON

	; otherwise, handle reselection.
	JUMP REL(resel_m)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;       Every phase comes back to here.
switch:
	JUMP REL(msgin), WHEN MSG_IN
	JUMP REL(dataout_gotos), IF DATA_OUT
	JUMP REL(datain_gotos), IF DATA_IN
	JUMP REL(status_phase), IF STATUS
	JUMP REL(command_phase), IF CMD
	JUMP REL(errmsg_out), WHEN MSG_OUT
	JUMP REL(dt_dataout_gotos), IF RES4
	JUMP REL(dt_datain_gotos), IF RES5
	INT PASS(NINT_ILI_PHASE)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

msgin:
; read the first byte
	MOVE FROM PASS(NTOFFSET(nt_rcvmsg)), WHEN MSG_IN
msgin2:
	JUMP REL(end), IF 0x00			; command complete message
	INT PASS(NINT_SDP_MSG), IF 0x02		; save data pointers
	JUMP REL(disc), IF 0x04			; disconnect message
	INT PASS(NINT_RP_MSG), IF 0x03		; restore data pointers
	INT PASS(NINT_MSGREJ), IF 0x07		; Message Reject
	JUMP REL(ext_msg_in), IF 0x01		; extended message
	JUMP REL(ignore_wide_residue), IF 0x23	; ignore wide residue
	INT PASS(NINT_UNS_MSG)			; unsupported message type

disc:
	MOVE 0x00 TO SCNTL2
	CLEAR ACK
	WAIT DISCONNECT
	INT PASS(NINT_DISC)

resel_disc:
	MOVE 0x00 TO SCNTL2
	CLEAR ACK
	WAIT DISCONNECT
	INT PASS(NINT_RESEL)

ext_msg_in:
	CLEAR ACK
	MOVE FROM PASS(NTOFFSET(nt_extmsg)), WHEN MSG_IN
	JUMP REL(wide_msg_in), IF 0x02
	JUMP REL(sync_msg_in), IF 0x03
	JUMP REL(ppr_msg_in), IF 0x06
	INT PASS(NINT_UNS_EXTMSG)

ignore_wide_residue:
	CLEAR ACK
	MOVE FROM PASS(NTOFFSET(nt_rcvmsg)), WHEN MSG_IN
	INT PASS(NINT_IWR)

ppr_msg_in:
	CLEAR ACK
	MOVE FROM PASS(NTOFFSET(nt_pprin)), WHEN MSG_IN
; don't ack the last byte until after the interrupt handler returns
	INT PASS(NINT_PPR), IF 0x04

sync_msg_in:
	CLEAR ACK
	MOVE FROM PASS(NTOFFSET(nt_syncin)), WHEN MSG_IN
; don't ack the last byte until after the interrupt handler returns
	INT PASS(NINT_SDTR), IF 0x01

; unsupported extended message
	INT PASS(NINT_UNS_EXTMSG)

wide_msg_in:
	CLEAR ACK
	MOVE FROM PASS(NTOFFSET(nt_widein)), WHEN MSG_IN
; don't ack the last byte until after the interrupt handler returns
	INT PASS(NINT_WDTR), IF 0x03

; unsupported extended message
	INT PASS(NINT_UNS_EXTMSG)

phase_mis_match:
	INT PASS(NINT_PMM)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

command_phase:
	MOVE FROM PASS(NTOFFSET(nt_cmd)), WHEN CMD
	JUMP REL(msgin), WHEN MSG_IN
	JUMP REL(switch)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

status_phase:
	MOVE FROM PASS(NTOFFSET(nt_status)), WHEN STATUS
	JUMP REL(switch), WHEN NOT MSG_IN
	MOVE FROM PASS(NTOFFSET(nt_rcvmsg)), WHEN MSG_IN


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

end:
	MOVE 0x00 TO SCNTL2
	CLEAR ACK
	WAIT DISCONNECT
	INT PASS(NINT_OK)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; The data in and data out scatter/gather dma lists are set up by
; the driver such that they're right justified in the table indirect
; array. In other words if the s/g list contains a single segment then
; only the last entry in the list is used. If the s/g list contains
; two entries then the last two entries are used, etc.. The jump table
; below skip over the unused entries. This way when a phase mismatch
; interrupt occurs I can easily compute how far into the list processing
; has proceeded and reset the pointers and the scratch register to
; properly restart the dma.

dataout_gotos:
	MOVE SCRATCHA0 TO SFBR
	INT PASS(NINT_TOOMUCHDATA), IF 0
	JUMP REL(dataout_1), IF 1
	JUMP REL(dataout_2), IF 2
	JUMP REL(dataout_3), IF 3
	JUMP REL(dataout_4), IF 4
	JUMP REL(dataout_5), IF 5
	JUMP REL(dataout_6), IF 6
	JUMP REL(dataout_7), IF 7
	JUMP REL(dataout_8), IF 8
	JUMP REL(dataout_9), IF 9
	JUMP REL(dataout_10), IF 10
	JUMP REL(dataout_11), IF 11
	JUMP REL(dataout_12), IF 12
	JUMP REL(dataout_13), IF 13
	JUMP REL(dataout_14), IF 14
	JUMP REL(dataout_15), IF 15
	JUMP REL(dataout_16), IF 16
	JUMP REL(dataout_17), IF 17
	INT PASS(NINT_TOOMUCHDATA)

dataout_17:	MOVE FROM PASS(NTOFFSET(nt_data[16])), WHEN DATA_OUT
dataout_16:	MOVE FROM PASS(NTOFFSET(nt_data[15])), WHEN DATA_OUT
dataout_15:	MOVE FROM PASS(NTOFFSET(nt_data[14])), WHEN DATA_OUT
dataout_14:	MOVE FROM PASS(NTOFFSET(nt_data[13])), WHEN DATA_OUT
dataout_13:	MOVE FROM PASS(NTOFFSET(nt_data[12])), WHEN DATA_OUT
dataout_12:	MOVE FROM PASS(NTOFFSET(nt_data[11])), WHEN DATA_OUT
dataout_11:	MOVE FROM PASS(NTOFFSET(nt_data[10])), WHEN DATA_OUT
dataout_10:	MOVE FROM PASS(NTOFFSET(nt_data[9])), WHEN DATA_OUT
dataout_9:	MOVE FROM PASS(NTOFFSET(nt_data[8])), WHEN DATA_OUT
dataout_8:	MOVE FROM PASS(NTOFFSET(nt_data[7])), WHEN DATA_OUT
dataout_7:	MOVE FROM PASS(NTOFFSET(nt_data[6])), WHEN DATA_OUT
dataout_6:	MOVE FROM PASS(NTOFFSET(nt_data[5])), WHEN DATA_OUT
dataout_5:	MOVE FROM PASS(NTOFFSET(nt_data[4])), WHEN DATA_OUT
dataout_4:	MOVE FROM PASS(NTOFFSET(nt_data[3])), WHEN DATA_OUT
dataout_3:	MOVE FROM PASS(NTOFFSET(nt_data[2])), WHEN DATA_OUT
dataout_2:	MOVE FROM PASS(NTOFFSET(nt_data[1])), WHEN DATA_OUT
dataout_1:	MOVE FROM PASS(NTOFFSET(nt_data[0])), WHEN DATA_OUT
do_list_end:
	MOVE 0 TO SCRATCHA0
	JUMP REL(switch)

;
; data in processing
;

datain_gotos:
	MOVE SCRATCHA0 TO SFBR
	INT PASS(NINT_TOOMUCHDATA), IF 0
	JUMP REL(datain_1), IF 1
	JUMP REL(datain_2), IF 2
	JUMP REL(datain_3), IF 3
	JUMP REL(datain_4), IF 4
	JUMP REL(datain_5), IF 5
	JUMP REL(datain_6), IF 6
	JUMP REL(datain_7), IF 7
	JUMP REL(datain_8), IF 8
	JUMP REL(datain_9), IF 9
	JUMP REL(datain_10), IF 10
	JUMP REL(datain_11), IF 11
	JUMP REL(datain_12), IF 12
	JUMP REL(datain_13), IF 13
	JUMP REL(datain_14), IF 14
	JUMP REL(datain_15), IF 15
	JUMP REL(datain_16), IF 16
	JUMP REL(datain_17), IF 17
	INT PASS(NINT_TOOMUCHDATA)

datain_17:	MOVE FROM PASS(NTOFFSET(nt_data[16])), WHEN DATA_IN
datain_16:	MOVE FROM PASS(NTOFFSET(nt_data[15])), WHEN DATA_IN
datain_15:	MOVE FROM PASS(NTOFFSET(nt_data[14])), WHEN DATA_IN
datain_14:	MOVE FROM PASS(NTOFFSET(nt_data[13])), WHEN DATA_IN
datain_13:	MOVE FROM PASS(NTOFFSET(nt_data[12])), WHEN DATA_IN
datain_12:	MOVE FROM PASS(NTOFFSET(nt_data[11])), WHEN DATA_IN
datain_11:	MOVE FROM PASS(NTOFFSET(nt_data[10])), WHEN DATA_IN
datain_10:	MOVE FROM PASS(NTOFFSET(nt_data[9])), WHEN DATA_IN
datain_9:	MOVE FROM PASS(NTOFFSET(nt_data[8])), WHEN DATA_IN
datain_8:	MOVE FROM PASS(NTOFFSET(nt_data[7])), WHEN DATA_IN
datain_7:	MOVE FROM PASS(NTOFFSET(nt_data[6])), WHEN DATA_IN
datain_6:	MOVE FROM PASS(NTOFFSET(nt_data[5])), WHEN DATA_IN
datain_5:	MOVE FROM PASS(NTOFFSET(nt_data[4])), WHEN DATA_IN
datain_4:	MOVE FROM PASS(NTOFFSET(nt_data[3])), WHEN DATA_IN
datain_3:	MOVE FROM PASS(NTOFFSET(nt_data[2])), WHEN DATA_IN
datain_2:	MOVE FROM PASS(NTOFFSET(nt_data[1])), WHEN DATA_IN
datain_1:	MOVE FROM PASS(NTOFFSET(nt_data[0])), WHEN DATA_IN
di_list_end:
	MOVE 0 TO SCRATCHA0
	JUMP REL(switch)


dt_dataout_gotos:
	MOVE SCRATCHA0 TO SFBR
	INT PASS(NINT_TOOMUCHDATA), IF 0
	JUMP REL(dt_dataout_1), IF 1
	JUMP REL(dt_dataout_2), IF 2
	JUMP REL(dt_dataout_3), IF 3
	JUMP REL(dt_dataout_4), IF 4
	JUMP REL(dt_dataout_5), IF 5
	JUMP REL(dt_dataout_6), IF 6
	JUMP REL(dt_dataout_7), IF 7
	JUMP REL(dt_dataout_8), IF 8
	JUMP REL(dt_dataout_9), IF 9
	JUMP REL(dt_dataout_10), IF 10
	JUMP REL(dt_dataout_11), IF 11
	JUMP REL(dt_dataout_12), IF 12
	JUMP REL(dt_dataout_13), IF 13
	JUMP REL(dt_dataout_14), IF 14
	JUMP REL(dt_dataout_15), IF 15
	JUMP REL(dt_dataout_16), IF 16
	JUMP REL(dt_dataout_17), IF 17
	INT PASS(NINT_TOOMUCHDATA)

dt_dataout_17:	MOVE FROM PASS(NTOFFSET(nt_data[16])), WHEN RES4
dt_dataout_16:	MOVE FROM PASS(NTOFFSET(nt_data[15])), WHEN RES4
dt_dataout_15:	MOVE FROM PASS(NTOFFSET(nt_data[14])), WHEN RES4
dt_dataout_14:	MOVE FROM PASS(NTOFFSET(nt_data[13])), WHEN RES4
dt_dataout_13:	MOVE FROM PASS(NTOFFSET(nt_data[12])), WHEN RES4
dt_dataout_12:	MOVE FROM PASS(NTOFFSET(nt_data[11])), WHEN RES4
dt_dataout_11:	MOVE FROM PASS(NTOFFSET(nt_data[10])), WHEN RES4
dt_dataout_10:	MOVE FROM PASS(NTOFFSET(nt_data[9])), WHEN RES4
dt_dataout_9:	MOVE FROM PASS(NTOFFSET(nt_data[8])), WHEN RES4
dt_dataout_8:	MOVE FROM PASS(NTOFFSET(nt_data[7])), WHEN RES4
dt_dataout_7:	MOVE FROM PASS(NTOFFSET(nt_data[6])), WHEN RES4
dt_dataout_6:	MOVE FROM PASS(NTOFFSET(nt_data[5])), WHEN RES4
dt_dataout_5:	MOVE FROM PASS(NTOFFSET(nt_data[4])), WHEN RES4
dt_dataout_4:	MOVE FROM PASS(NTOFFSET(nt_data[3])), WHEN RES4
dt_dataout_3:	MOVE FROM PASS(NTOFFSET(nt_data[2])), WHEN RES4
dt_dataout_2:	MOVE FROM PASS(NTOFFSET(nt_data[1])), WHEN RES4
dt_dataout_1:	MOVE FROM PASS(NTOFFSET(nt_data[0])), WHEN RES4
dt_do_list_end:
	MOVE 0 TO SCRATCHA0
	JUMP REL(switch)

;
; data in processing
;

dt_datain_gotos:
	MOVE SCRATCHA0 TO SFBR
	INT PASS(NINT_TOOMUCHDATA), IF 0
	JUMP REL(dt_datain_1), IF 1
	JUMP REL(dt_datain_2), IF 2
	JUMP REL(dt_datain_3), IF 3
	JUMP REL(dt_datain_4), IF 4
	JUMP REL(dt_datain_5), IF 5
	JUMP REL(dt_datain_6), IF 6
	JUMP REL(dt_datain_7), IF 7
	JUMP REL(dt_datain_8), IF 8
	JUMP REL(dt_datain_9), IF 9
	JUMP REL(dt_datain_10), IF 10
	JUMP REL(dt_datain_11), IF 11
	JUMP REL(dt_datain_12), IF 12
	JUMP REL(dt_datain_13), IF 13
	JUMP REL(dt_datain_14), IF 14
	JUMP REL(dt_datain_15), IF 15
	JUMP REL(dt_datain_16), IF 16
	JUMP REL(dt_datain_17), IF 17
	INT PASS(NINT_TOOMUCHDATA)

dt_datain_17:	MOVE FROM PASS(NTOFFSET(nt_data[16])), WHEN RES5
dt_datain_16:	MOVE FROM PASS(NTOFFSET(nt_data[15])), WHEN RES5
dt_datain_15:	MOVE FROM PASS(NTOFFSET(nt_data[14])), WHEN RES5
dt_datain_14:	MOVE FROM PASS(NTOFFSET(nt_data[13])), WHEN RES5
dt_datain_13:	MOVE FROM PASS(NTOFFSET(nt_data[12])), WHEN RES5
dt_datain_12:	MOVE FROM PASS(NTOFFSET(nt_data[11])), WHEN RES5
dt_datain_11:	MOVE FROM PASS(NTOFFSET(nt_data[10])), WHEN RES5
dt_datain_10:	MOVE FROM PASS(NTOFFSET(nt_data[9])), WHEN RES5
dt_datain_9:	MOVE FROM PASS(NTOFFSET(nt_data[8])), WHEN RES5
dt_datain_8:	MOVE FROM PASS(NTOFFSET(nt_data[7])), WHEN RES5
dt_datain_7:	MOVE FROM PASS(NTOFFSET(nt_data[6])), WHEN RES5
dt_datain_6:	MOVE FROM PASS(NTOFFSET(nt_data[5])), WHEN RES5
dt_datain_5:	MOVE FROM PASS(NTOFFSET(nt_data[4])), WHEN RES5
dt_datain_4:	MOVE FROM PASS(NTOFFSET(nt_data[3])), WHEN RES5
dt_datain_3:	MOVE FROM PASS(NTOFFSET(nt_data[2])), WHEN RES5
dt_datain_2:	MOVE FROM PASS(NTOFFSET(nt_data[1])), WHEN RES5
dt_datain_1:	MOVE FROM PASS(NTOFFSET(nt_data[0])), WHEN RES5
dt_di_list_end:
	MOVE 0 TO SCRATCHA0
	JUMP REL(switch)
