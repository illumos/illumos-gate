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
/*	from S5R3 sys/tihdr.h	10.2" */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


/* #ident	"@(#)kern-port:sys/tihdr.h	10.2" */

/*
 * The following is all the information
 * needed by the Transport Service Interface.
 */

#ifndef _nettli_tihdr_h
#define _nettli_tihdr_h

/* 
 * The following are the definitions of the Transport
 * Service Interface primitives.
 */

/* 
 * Primitives that are initiated by the transport user.
 */
#define	T_CONN_REQ	0	/* connection request     */
#define T_CONN_RES	1	/* connection response    */
#define T_DISCON_REQ	2	/* disconnect request     */
#define T_DATA_REQ	3	/* data request	          */
#define T_EXDATA_REQ	4	/* expedited data request */
#define T_INFO_REQ	5	/* information request    */
#define T_BIND_REQ	6	/* bind request		  */
#define T_UNBIND_REQ	7	/* unbind request	  */
#define T_UNITDATA_REQ	8	/* unitdata request       */
#define T_OPTMGMT_REQ   9	/* manage options req     */
#define T_ORDREL_REQ   10       /* orderly release req    */

/* 
 * Primitives that are initiated by the transport provider.
 */

#define T_CONN_IND	11	/* connection indication      */
#define T_CONN_CON	12	/* connection confirmation    */
#define T_DISCON_IND	13	/* disconnect indication      */
#define T_DATA_IND	14	/* data indication	      */
#define T_EXDATA_IND	15	/* expeditied data indication */
#define T_INFO_ACK	16	/* information acknowledgment */
#define T_BIND_ACK	17	/* bind acknowledment	      */
#define T_ERROR_ACK	18	/* error acknowledgment       */
#define T_OK_ACK	19	/* ok acknowledgment          */
#define T_UNITDATA_IND	20	/* unitdata indication	      */
#define T_UDERROR_IND	21	/* unitdata error indication  */
#define T_OPTMGMT_ACK   22      /* manage options ack         */
#define T_ORDREL_IND    23      /* orderly release ind 	      */

/*
 * The following are the events that drive the state machine
 */
/* Initialization events */
#define TE_BIND_REQ	0	/* bind request		  		*/
#define TE_UNBIND_REQ	1	/* unbind request	  		*/
#define TE_OPTMGMT_REQ  2	/* manage options req     		*/
#define TE_BIND_ACK	3	/* bind acknowledment	      		*/
#define TE_OPTMGMT_ACK  4       /* manage options ack         		*/
#define TE_ERROR_ACK	5	/* error acknowledgment       		*/
#define TE_OK_ACK1	6	/* ok ack  seqcnt == 0 		  	*/
#define TE_OK_ACK2	7	/* ok ack  seqcnt == 1, q == resq      	*/
#define TE_OK_ACK3	8	/* ok ack  seqcnt == 1, q != resq       */
#define TE_OK_ACK4	9	/* ok ack  seqcnt > 1        		*/

/* Connection oriented events */
#define	TE_CONN_REQ	10	/* connection request     		*/
#define TE_CONN_RES	11	/* connection response    		*/
#define TE_DISCON_REQ	12	/* disconnect request     		*/
#define TE_DATA_REQ	13	/* data request	          		*/
#define TE_EXDATA_REQ	14	/* expedited data request 		*/
#define TE_ORDREL_REQ   15      /* orderly release req    		*/
#define TE_CONN_IND	16	/* connection indication      		*/
#define TE_CONN_CON	17	/* connection confirmation    		*/
#define TE_DATA_IND	18	/* data indication	      		*/
#define TE_EXDATA_IND	19	/* expedited data indication 		*/
#define TE_ORDREL_IND   20      /* orderly release ind 	      		*/
#define TE_DISCON_IND1	21	/* disconnect indication seq == 0      	*/
#define TE_DISCON_IND2	22	/* disconnect indication seq == 1   	*/
#define TE_DISCON_IND3	23	/* disconnect indication seq > 1  	*/
#define TE_PASS_CONN	24	/* pass connection 	      		*/

/* Unit data events */
#define TE_UNITDATA_REQ	25	/* unitdata request       		*/
#define TE_UNITDATA_IND	26	/* unitdata indication	      		*/
#define TE_UDERROR_IND	27	/* unitdata error indication  		*/

#define TE_NOEVENTS	28
/*
 * The following are the possible states of the Transport
 * Service Interface
 */

#define TS_UNBND		0	/* unbound	                */
#define	TS_WACK_BREQ		1	/* waiting ack of BIND_REQ      */
#define TS_WACK_UREQ		2	/* waiting ack of UNBIND_REQ    */
#define TS_IDLE			3	/* idle 		        */
#define TS_WACK_OPTREQ		4	/* wait ack options request     */
#define TS_WACK_CREQ		5	/* waiting ack of CONN_REQ      */
#define TS_WCON_CREQ		6	/* waiting confirm of CONN_REQ  */
#define	TS_WRES_CIND		7	/* waiting response of CONN_IND */
#define TS_WACK_CRES		8	/* waiting ack of CONN_RES      */
#define TS_DATA_XFER		9	/* data transfer		*/
#define TS_WIND_ORDREL	 	10	/* releasing rd but not wr      */
#define TS_WREQ_ORDREL		11      /* wait to release wr but not rd*/
#define TS_WACK_DREQ6		12	/* waiting ack of DISCON_REQ    */
#define TS_WACK_DREQ7		13	/* waiting ack of DISCON_REQ    */
#define TS_WACK_DREQ9		14	/* waiting ack of DISCON_REQ    */
#define TS_WACK_DREQ10		15	/* waiting ack of DISCON_REQ    */
#define TS_WACK_DREQ11		16	/* waiting ack of DISCON_REQ    */

#define TS_NOSTATES		17


/* 
 * The following structure definitions define the format of the
 * stream message block of the above primitives.
 * (everything is declared long to ensure proper alignment
 *  across different machines)
 */

/* connection request */

struct T_conn_req {
	long	PRIM_type;	/* always T_CONN_REQ  */
	long	DEST_length;	/* dest addr length   */
	long	DEST_offset;	/* dest addr offset   */
	long	OPT_length;	/* options length     */
	long	OPT_offset;	/* options offset     */
};

/* connect response */

struct T_conn_res {
	long    PRIM_type;	/* always T_CONN_RES       */
	void	*QUEUE_ptr;	/* responding queue ptr    */
	long    OPT_length;	/* options length          */
	long	OPT_offset;	/* options offset          */
	long    SEQ_number;	/* sequence number          */
};

/* disconnect request */

struct T_discon_req {
	long    PRIM_type;	/* always T_DISCON_REQ */
	long    SEQ_number;	/* sequnce number      */
};

/* data request */

struct T_data_req {
	long	PRIM_type;	/* always T_DATA_REQ */
	long	MORE_flag;	/* more data	     */
};

/* expedited data request */

struct T_exdata_req {
	long	PRIM_type;	/* always T_EXDATA_REQ */
	long	MORE_flag;	/* more data	       */
};

/* information request */

struct T_info_req {
	long	PRIM_type;	/* always T_INFO_REQ */
};

/* bind request */

struct T_bind_req {
	long		PRIM_type;	/* always T_BIND_REQ            */
	long		ADDR_length;	/* addr length	                */
	long		ADDR_offset;	/* addr offset	                */
	unsigned long	CONIND_number;	/*connect indications requested */
};

/* unbind request */

struct T_unbind_req {
	long	PRIM_type;	/* always T_UNBIND_REQ */
};

/* unitdata request */

struct T_unitdata_req {
	long	PRIM_type;	/* always T_UNITDATA_REQ  */
	long	DEST_length;	/* dest addr length       */
	long	DEST_offset;	/* dest addr offset       */
	long	OPT_length;	/* options length         */
	long	OPT_offset;	/* options offset         */
};

/* manage options request */

struct T_optmgmt_req {
	long	PRIM_type;	/* always T_OPTMGMT_REQ   */
	long	OPT_length;	/* options length         */
	long	OPT_offset;	/* options offset         */
	long    MGMT_flags;	/* options flags          */
};

/* orderly release request */

struct T_ordrel_req {
	long	PRIM_type;	/* always T_ORDREL_REQ */
};

/* connect indication */

struct T_conn_ind {
	long	PRIM_type;	/* always T_CONN_IND */
	long	SRC_length;	/* src addr length   */
	long	SRC_offset;	/* src addr offset   */
	long	OPT_length;	/* option length     */
	long    OPT_offset;	/* option offset     */
	long    SEQ_number;	/* sequnce number    */
};

/* connect confirmation */

struct T_conn_con {
	long	PRIM_type;	/* always T_CONN_CON      */
	long	RES_length;	/* responding addr length */
	long	RES_offset;	/* responding addr offset */
	long	OPT_length;	/* option length          */
	long    OPT_offset;	/* option offset          */
};

/* disconnect indication */

struct T_discon_ind {
	long	PRIM_type;	/* always T_DISCON_IND 	*/
	long	DISCON_reason;	/* disconnect reason	*/
	long    SEQ_number;	/* sequnce number       */
};

/* data indication */

struct T_data_ind {
	long 	PRIM_type;	/* always T_DATA_IND */
	long	MORE_flag;	/* more data 	     */
};

/* expedited data indication */

struct T_exdata_ind {
	long	PRIM_type;	/* always T_EXDATA_IND */
	long	MORE_type;	/* more data           */
};

/* information acknowledgment */

struct T_info_ack {
	long	PRIM_type;	/* always T_INFO_ACK     */
	long	TSDU_size;	/* max TSDU size         */
	long	ETSDU_size;	/* max ETSDU size        */
	long	CDATA_size;	/* max connect data size */
	long	DDATA_size;	/* max discon data size  */
	long	ADDR_size;	/* address size		 */
	long	OPT_size;	/* options size		 */
	long    TIDU_size;	/* max TIDU size         */
	long    SERV_type;	/* provider service type */
	long    CURRENT_state;  /* current state         */
};

/* bind acknowledgment */

struct T_bind_ack {
	long		PRIM_type;	/* always T_BIND_ACK        */
	long		ADDR_length;	/* addr length              */
	long		ADDR_offset;	/* addr offset              */
	unsigned long	CONIND_number;	/* connect ind to be queued */
};

/* error acknowledgment */

struct T_error_ack { 
	long 	PRIM_type;	/* always T_ERROR_ACK  */
	long	ERROR_prim;	/* primitive in error  */
	long	TLI_error;	/* TLI error code      */
	long	UNIX_error;	/* UNIX error code     */
};

/* ok acknowledgment */

struct T_ok_ack {
	long 	PRIM_type;	/* always T_OK_ACK   */
	long	CORRECT_prim;	/* correct primitive */
};

/* unitdata indication */

struct T_unitdata_ind {
	long	PRIM_type;	/* always T_UNITDATA_IND  */
	long	SRC_length;	/* source addr length     */
	long	SRC_offset;	/* source addr offset     */
	long	OPT_length;	/* options length         */
	long	OPT_offset;	/* options offset         */
};

/* unitdata error indication */

struct T_uderror_ind {
	long	PRIM_type;	/* always T_UDERROR_IND   */
	long	DEST_length;	/* dest addr length       */
	long	DEST_offset;	/* dest addr offset       */
	long	OPT_length;	/* options length         */
	long	OPT_offset;	/* options offset         */
	long	ERROR_type;	/* error type	          */
};

/* manage options ack */

struct T_optmgmt_ack {
	long	PRIM_type;	/* always T_OPTMGMT_ACK   */
	long	OPT_length;	/* options length         */
	long	OPT_offset;	/* options offset         */
	long    MGMT_flags;	/* managment flags        */
};

/* orderly release indication */

struct T_ordrel_ind {
	long	PRIM_type;	/* always T_ORDREL_IND */
};

/*
 * The following is a union of the primitives
 */
union T_primitives {
	long			type;		/* primitive type     */
	struct T_conn_req	conn_req;	/* connect request    */
	struct T_conn_res	conn_res;	/* connect response   */
	struct T_discon_req	discon_req;	/* disconnect request */
	struct T_data_req	data_req;	/* data request       */
	struct T_exdata_req	exdata_req;	/* expedited data req */
	struct T_info_req	info_req;	/* information req    */
	struct T_bind_req	bind_req;	/* bind request       */
	struct T_unbind_req	unbind_req;	/* unbind request     */
	struct T_unitdata_req	unitdata_req;	/* unitdata requset   */
	struct T_optmgmt_req	optmgmt_req;	/* manage opt req     */
	struct T_ordrel_req	ordrel_req;	/* orderly rel req    */
	struct T_conn_ind	conn_ind;	/* connect indication */
	struct T_conn_con	conn_con;	/* connect corfirm    */
	struct T_discon_ind	discon_ind;	/* discon indication  */
	struct T_data_ind	data_ind;	/* data indication    */
	struct T_exdata_ind	exdata_ind;	/* expedited data ind */
	struct T_info_ack	info_ack;	/* info ack	      */
	struct T_bind_ack	bind_ack;	/* bind ack	      */
	struct T_error_ack	error_ack;	/* error ack	      */
	struct T_ok_ack		ok_ack;		/* ok ack	      */
	struct T_unitdata_ind	unitdata_ind;	/* unitdata ind       */
	struct T_uderror_ind	uderror_ind;	/* unitdata error ind */
	struct T_optmgmt_ack	optmgmt_ack;	/* manage opt ack     */
	struct T_ordrel_ind	ordrel_ind;	/* orderly rel ind    */
};

#endif /*!_nettli_tihdr_h*/
