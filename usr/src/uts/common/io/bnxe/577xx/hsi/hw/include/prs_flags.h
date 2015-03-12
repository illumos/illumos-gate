#ifndef PRS_FLAGS_H
#define PRS_FLAGS_H

/**
* This file defines constants of the parsing flags that are attached to the start packet message of the parser
*/

//error flags
#define PRS_ERR_FLG_BAD_IP_VERSION					1
#define PRS_ERR_FLG_BAD_IP_HEADER_LENGTH            2
#define PRS_ERR_FLG_BAD_IP_TOTAL_LENGTH				4
#define PRS_ERR_FLG_BAD_IP_HEADER_CHECKSUM          8
#define PRS_ERR_FLG_BAD_TCP_HEADER_CHECKSUM         16
#define PRS_ERR_FLG_BAD_UDP_LENGTH					32
#define PRS_ERR_FLG_PACKET_TOO_SMALL				64
#define PRS_ERR_FLG_ZERO_UDP_IPV6_CHECKSUM          128
#define PRS_ERR_TCP_OPTIONS_LENGTH					256

#endif //PRS_FLAGS_H

