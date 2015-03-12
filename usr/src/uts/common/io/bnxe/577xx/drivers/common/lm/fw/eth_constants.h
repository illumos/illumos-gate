#ifndef __ETH_CONSTANTS_H_
#define __ETH_CONSTANTS_H_

/* eth hsi version */
#define ETH_FP_HSI_VERSION (ETH_FP_HSI_VER_2)


/* Ethernet Ring parameters */
#define X_ETH_LOCAL_RING_SIZE	        13
#define FIRST_BD_IN_PKT					0
#define PARSE_BD_INDEX					1
#define NUM_OF_ETH_BDS_IN_PAGE			((PAGE_SIZE)/(STRUCT_SIZE(eth_tx_bd)/8))
#define U_ETH_NUM_OF_SGES_TO_FETCH		8
#define U_ETH_MAX_SGES_FOR_PACKET		3

/* Rx ring params */
#define U_ETH_LOCAL_BD_RING_SIZE	8	
#define U_ETH_LOCAL_SGE_RING_SIZE	10	
#define U_ETH_SGL_SIZE	8
/* The fw will padd the buffer with this value, so the IP header will be align to 4 Byte */
#define IP_HEADER_ALIGNMENT_PADDING	2

#define U_ETH_SGES_PER_PAGE_INVERSE_MASK	   (0xFFFF - ((PAGE_SIZE/((STRUCT_SIZE(eth_rx_sge))/8))-1))

#define TU_ETH_CQES_PER_PAGE	(PAGE_SIZE/(STRUCT_SIZE(eth_rx_cqe)/8))
#define U_ETH_BDS_PER_PAGE		(PAGE_SIZE/(STRUCT_SIZE(eth_rx_bd)/8))
#define U_ETH_SGES_PER_PAGE		(PAGE_SIZE/(STRUCT_SIZE(eth_rx_sge)/8))

#define U_ETH_BDS_PER_PAGE_MASK	  				(U_ETH_BDS_PER_PAGE-1)
#define U_ETH_CQE_PER_PAGE_MASK	  				(TU_ETH_CQES_PER_PAGE-1)
#define U_ETH_SGES_PER_PAGE_MASK				(U_ETH_SGES_PER_PAGE-1)

//tpa constants
#define U_ETH_UNDEFINED_Q 0xFF

#define T_ETH_INDIRECTION_TABLE_SIZE		128
#define T_ETH_RSS_KEY						10
#define ETH_NUM_OF_RSS_ENGINES_E2				72

// number of filter rules 
#define FILTER_RULES_COUNT 16
// number of multicast rules 
#define MULTICAST_RULES_COUNT 16
// number of classify rules 
#define CLASSIFY_RULES_COUNT 16

/*The CRC32 seed, that is used for the hash(reduction) multicast address */
#define ETH_CRC32_HASH_SEED			0x00000000

#define ETH_CRC32_HASH_BIT_SIZE		(8)
#define ETH_CRC32_HASH_MASK			EVAL((1<<ETH_CRC32_HASH_BIT_SIZE)-1)

/* Maximal L2 clients supported */
#define ETH_MAX_RX_CLIENTS_E1				18
#define ETH_MAX_RX_CLIENTS_E1H				28
#define ETH_MAX_RX_CLIENTS_E2				152

/* Maximal statistics client Ids */
#define MAX_STAT_COUNTER_ID_E1				36
#define MAX_STAT_COUNTER_ID_E1H				56
#define MAX_STAT_COUNTER_ID_E2				140

#define MAX_MAC_CREDIT_E1					192	/* Per Chip */
#define MAX_MAC_CREDIT_E1H					256	/* Per Chip */				  
#define MAX_MAC_CREDIT_E2					272	/* Per Path */
#define MAX_VLAN_CREDIT_E1					0	/* Per Chip */
#define MAX_VLAN_CREDIT_E1H					0	/* Per Chip */
#define MAX_VLAN_CREDIT_E2					272	/* Per Path */


/* Maximal aggregation queues supported */
#define ETH_MAX_AGGREGATION_QUEUES_E1		32
#define ETH_MAX_AGGREGATION_QUEUES_E1H_E2               64


//number of multicast bins for approximate match
#define ETH_NUM_OF_MCAST_BINS		256
#define ETH_NUM_OF_MCAST_ENGINES_E2             72

//min CQEs
#define ETH_MIN_RX_CQES_WITHOUT_TPA                     (MAX_RAMRODS_PER_PORT + 3)
#define ETH_MIN_RX_CQES_WITH_TPA_E1                     (ETH_MAX_AGGREGATION_QUEUES_E1 + ETH_MIN_RX_CQES_WITHOUT_TPA)
#define ETH_MIN_RX_CQES_WITH_TPA_E1H_E2         (ETH_MAX_AGGREGATION_QUEUES_E1H_E2 + ETH_MIN_RX_CQES_WITHOUT_TPA)

#define DISABLE_STATISTIC_COUNTER_ID_VALUE 0
#endif /*__ETH_CONSTANTS_H_ */

