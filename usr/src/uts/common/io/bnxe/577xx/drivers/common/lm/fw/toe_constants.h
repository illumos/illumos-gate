#ifndef __TOE_CONSTANTS_H_
#define __TOE_CONSTANTS_H_

/**
* This file defines HSI constatnts for the TOE flows
*/
											  

/********* thresholds of xOff xOn *****************************************/			  
#define GRQ_XOFF_TH		 (64)				
#define GRQ_XOFF_OOO_TH  (96) // (1.5*GRQ_XOFF_TH)				
										
//(maximum pending incoming packet msgs) * (maximum completions) + (maximum ramrods)
#define CQ_XOFF_TH  ((64*6) + MAX_RAMRODS_PER_PORT)

#define	GRQ_XON_TH 		(2*GRQ_XOFF_TH)
#define	CQ_XON_TH  		(2*CQ_XOFF_TH)


/********* TOE RSS indirection table *****************************************/
#define	TOE_INDIRECTION_TABLE_SIZE		128	//Size in bytes 

/********* Roll Over Param Constants *****************************************/
#define TOE_XSTORM_IP_ID_INIT_LO 0
#define TOE_XSTORM_IP_ID_INIT_HI 0x8000
#define TOE_XSTORM_IP_ID_INIT_ALL 0
/************************************************************************/

/********* xcm minimum global delayed ack max count**********************/
#define TCP_XCM_MIN_GLB_DEL_ACK_MAX_CNT 1
/************************************************************************/

/********* tstorm maximum dup ack threshold *****************************/
#define TCP_TSTORM_MAX_DUP_ACK_TH 255
/************************************************************************/


#endif /*__TOE_CONSTANTS_H_ */
