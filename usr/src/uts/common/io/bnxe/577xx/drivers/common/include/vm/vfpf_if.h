#ifndef VF_PF_SW_IF_H
#define VF_PF_SW_IF_H


/* 
 * common flags - right now it duplicates the #defines in the PF code -
 * TODO: put in another common header file
 */
#define SW_VFPF_QUEUE_FLG_TPA   		0x0001
#define SW_VFPF_QUEUE_FLG_CACHE_ALIGN   	0x0002
#define SW_VFPF_QUEUE_FLG_STATS		0x0004
#define SW_VFPF_QUEUE_FLG_OV    		0x0008
#define SW_VFPF_QUEUE_FLG_VLAN  		0x0010
#define SW_VFPF_QUEUE_FLG_COS   		0x0020
#define SW_VFPF_QUEUE_FLG_HC		0x0040
#define SW_VFPF_QUEUE_FLG_DHC		0x0080

#define SW_VFPF_QUEUE_DROP_IP_CS_ERR	(1 << 0)
#define SW_VFPF_QUEUE_DROP_TCP_CS_ERR	(1 << 1)
#define SW_VFPF_QUEUE_DROP_TTL0		(1 << 2)
#define SW_VFPF_QUEUE_DROP_UDP_CS_ERR	(1 << 3)

#define SW_VFPF_VFDEF_INFO_AUX_DIRECT_DQ   0x01

enum {
	SW_PFVF_STATUS_WAITING = 0,
	SW_PFVF_STATUS_SUCCESS,
	SW_PFVF_STATUS_FAILURE,
	SW_PFVF_STATUS_NOT_SUPPORTED,
    SW_PFVF_STATUS_MISMATCH_PF_VF_VERSION,
    SW_PFVF_STATUS_NO_RESOURCE,
    SW_PFVF_STATUS_MISMATCH_FW_HSI
};

/*  Headers */
struct vf_pf_msg_hdr {
	u16 opcode;

#define PFVF_IF_VERSION     	   1
	u8  if_ver;
	u8  opcode_ver;
	u32 resp_msg_offset;
};

struct pf_vf_msg_hdr {
	u8 status;
	u8 opcode_ver;
	u16 opcode;
};

/* simple response */
struct pf_vf_msg_resp {
	struct pf_vf_msg_hdr    hdr;
};


/* Acquire */
struct vf_pf_msg_acquire {
	struct vf_pf_msg_hdr hdr;

	struct sw_vf_pf_vfdev_info
	{
		/* the following fields are for debug purposes */
		u8  vf_id;      	/* ME register value */
		u8  vf_os;      	/* e.g. Linux, W2K8 */
        u8  vf_aux;
        u8  fp_hsi_ver;
        u32 vf_fw_hsi_version;  /* e.g. 6.0.12 */
	} vfdev_info;

	struct sw_vf_pf_resc_request
	{
		u8  num_rxqs;
		u8  num_txqs;
		u8  num_sbs;
		u8  num_mac_filters;
		u8  num_vlan_filters;
		u8  num_mc_filters;
        u8  reserved1;
        u8  reserved2;

	/* TODO: future:
		statistics resc?, other resc?   */
	} resc_request;
};


/* simple operation request on queue */
struct vf_pf_msg_q_op {
	struct vf_pf_msg_hdr    hdr;
	u8      		vf_qid;
	u8			padding[3];
};

struct vf_pf_msg_rss {
	struct vf_pf_msg_hdr    hdr;
	u32   					rss_flags;

	/* Number hash bits to take into an account */
	u8  					rss_result_mask;

	u8						ind_table_size;
	u8						rss_key_size;

	/* Indirection table */
	u8  					ind_table[T_ETH_INDIRECTION_TABLE_SIZE];

	/* RSS hash values */
	u32 					rss_key[10];
};

struct vf_pf_msg_rsc {
    struct vf_pf_msg_hdr    hdr;
    u32                     rsc_ipv4_state;
    u32                     rsc_ipv6_state;
};

struct sw_hw_sb_info {
	u8 hw_sb_id;	/* aka absolute igu id, used to ack the sb */
	u8 sb_qid;	/* used to update DHC for sb */
};

struct pf_vf_msg_acquire_resp {
	struct pf_vf_msg_hdr hdr;
	
	struct sw_pf_vf_pfdev_info
	{
		u32 chip_num;
		
		u32 pf_cap;
		#define PFVF_CAP_RSS        0x00000001
		#define PFVF_CAP_DHC        0x00000002
		#define PFVF_CAP_TPA        0x00000004
                #define PFVF_DEBUG          0x80000000
		
		u16 db_size;
		u8  indices_per_sb;
		u8  padding;
	} pfdev_info;

	struct sw_pf_vf_resc
	{  
		/* 
		 * in case of status NO_RESOURCE in message hdr, pf will fill
		 * this struct with suggested amount of resources for next
		 * acquire request 
		 */
	
		#define PFVF_MAX_QUEUES_PER_VF         16
		#define PFVF_MAX_SBS_PER_VF            16
		struct sw_hw_sb_info hw_sbs[PFVF_MAX_SBS_PER_VF];
		u8	hw_qid[PFVF_MAX_QUEUES_PER_VF];
		u8	num_rxqs;
		u8	num_txqs;
		u8	num_sbs;
		u8	num_mac_filters;
		u8	num_vlan_filters;
		u8	num_mc_filters;
		u8  igu_test_cnt;
		u8  igu_cnt;
		u8 	permanent_mac_addr[8];
		u8 	current_mac_addr[8];
	/* TODO: stats resc? cid for the ramrod? stats_id? spq prod id? */
	} resc;
};

/* Init VF */
struct vf_pf_msg_init_vf {
	struct vf_pf_msg_hdr hdr;
	
	u64 sb_addr[PFVF_MAX_SBS_PER_VF]; /* vf_sb based */
	u64 spq_addr;
	u64 stats_addr;
};

/* Setup Queue */
struct vf_pf_msg_setup_q {
	struct vf_pf_msg_hdr hdr;
	u8 vf_qid;			/* index in hw_qid[] */

	u8 param_valid;
	#define VFPF_RXQ_VALID		0x01
	#define VFPF_TXQ_VALID		0x02

	u16 padding;

	struct sw_vf_pf_rxq_params {
		/* physical addresses */
		u64 rcq_addr;
		u64 rcq_np_addr;
		u64 rxq_addr;
		u64 sge_addr;
		
		/* sb + hc info */
		u8  vf_sb;		/* index in hw_sbs[] */
		u8  sb_index;           /* Index in the SB */
		u16 hc_rate;		/* desired interrupts per sec. */
					/* valid iff VFPF_QUEUE_FLG_HC */
		/* rx buffer info */
		u16 mtu;
		u16 buf_sz;
		u16 flags;              /* VFPF_QUEUE_FLG_X flags */
		u16 stat_id;		/* valid iff VFPF_QUEUE_FLG_STATS */

		/* valid iff VFPF_QUEUE_FLG_TPA */
		u16 sge_buf_sz;		
		u16 tpa_agg_sz;
		u8 max_sge_pkt;

		u8 drop_flags;		/* VFPF_QUEUE_DROP_X, for Linux all should 
					 * be turned off, see setup_rx_queue() 
					 * for reference
					 */

		u8 cache_line_log;	/* VFPF_QUEUE_FLG_CACHE_ALIGN 
					 * see init_rx_queue()
					 */
		u8 padding;
	} rxq;

	struct sw_vf_pf_txq_params {
		/* physical addresses */
		u64 txq_addr;

		/* sb + hc info */
		u8  vf_sb;		/* index in hw_sbs[] */
		u8  sb_index;		/* Index in the SB */
		u16 hc_rate;		/* desired interrupts per sec. */
					/* valid iff VFPF_QUEUE_FLG_HC */
		u32 flags;		/* VFPF_QUEUE_FLG_X flags */
		u16 stat_id;		/* valid iff VFPF_QUEUE_FLG_STATS */
		u8  traffic_type;	/* see in setup_context() */
		u8  padding;
	} txq;
};


/* Set Queue Filters */
struct vf_pf_q_mac_vlan_filter {
	u32 flags;
	#define VFPF_Q_FILTER_DEST_MAC_PRESENT 	0x01
	#define VFPF_Q_FILTER_VLAN_TAG_PRESENT	0x02

	#define VFPF_Q_FILTER_SET_MAC			0x100
	
	u8  dest_mac[6];
	u16 vlan_tag;
};

struct vf_pf_msg_set_q_filters {
	struct vf_pf_msg_hdr hdr;

	u32 flags;
	#define VFPF_SET_Q_FILTERS_MAC_VLAN_CHANGED 	0x01
	#define VFPF_SET_Q_FILTERS_MULTICAST_CHANGED	0x02
	#define VFPF_SET_Q_FILTERS_RX_MASK_CHANGED  	0x04
	
	u8 vf_qid;			/* index in hw_qid[] */
	u8 n_mac_vlan_filters;
	u8 n_multicast;
	u8 padding;
	
	#define PFVF_MAX_MAC_FILTERS			16
	#define PFVF_MAX_VLAN_FILTERS       		16
//	#define PFVF_MAX_MAC_FILTERS			1
//	#define PFVF_MAX_VLAN_FILTERS       		1
	#define PFVF_MAX_FILTERS 			(PFVF_MAX_MAC_FILTERS +\
							 PFVF_MAX_VLAN_FILTERS)
	struct vf_pf_q_mac_vlan_filter filters[PFVF_MAX_FILTERS];
	
	#define PFVF_MAX_MULTICAST_PER_VF   		32
//	#define PFVF_MAX_MULTICAST_PER_VF   		1
	u8  multicast[PFVF_MAX_MULTICAST_PER_VF][6];
	
	u32 rx_mask;
	#define VFPF_RX_MASK_ACCEPT_NONE		0x00000000
	#define VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST	0x00000001
	#define VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST	0x00000002
	#define VFPF_RX_MASK_ACCEPT_ALL_UNICAST		0x00000004
	#define VFPF_RX_MASK_ACCEPT_ALL_MULTICAST	0x00000008
	#define VFPF_RX_MASK_ACCEPT_BROADCAST		0x00000010
	/* TODO: #define VFPF_RX_MASK_ACCEPT_ANY_VLAN	0x00000020 */
};


/* close VF (disable VF) */
struct vf_pf_msg_close_vf {
	struct vf_pf_msg_hdr	hdr;
	u16			vf_id;  /* for debug */
	u16			padding;			
};

/* rlease the VF's acquired resources */
struct vf_pf_msg_release_vf {
	struct vf_pf_msg_hdr	hdr;
	u16			vf_id;  /* for debug */
	u16			padding;
};


union vf_pf_msg {
	struct vf_pf_msg_hdr		hdr;
	struct vf_pf_msg_acquire	acquire;
	struct vf_pf_msg_init_vf	init_vf;
	struct vf_pf_msg_close_vf	close_vf;
	struct vf_pf_msg_q_op		q_op;
	struct vf_pf_msg_setup_q	setup_q;
	struct vf_pf_msg_set_q_filters	set_q_filters;
	struct vf_pf_msg_release_vf	release_vf;
	struct vf_pf_msg_rss		update_rss;
    struct vf_pf_msg_rsc        update_rsc;
};


union pf_vf_msg {
	struct pf_vf_msg_resp		resp;
	struct pf_vf_msg_acquire_resp	acquire_resp;
};

typedef struct {
	u32 req_sz;
	u32 resp_sz;
} msg_sz_t;

#define PFVF_OP_VER_MAX(op_arry)  (sizeof(op_arry)/sizeof(*op_arry) - 1)

static const msg_sz_t acquire_req_sz[] = {
	/* sizeof(vf_pf_msg_acquire) - offsetof(struct vf_pf_msg_acquire, fieldX), */
	{sizeof(struct vf_pf_msg_acquire),
	sizeof(struct pf_vf_msg_acquire_resp)}
};
#define PFVF_ACQUIRE_VER  PFVF_OP_VER_MAX(acquire_req_sz)	

static const msg_sz_t init_vf_req_sz[] = {
	{sizeof(struct vf_pf_msg_init_vf), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_INIT_VF_VER  PFVF_OP_VER_MAX(init_vf_req_sz)

static const msg_sz_t setup_q_req_sz[] = {
	{sizeof(struct vf_pf_msg_setup_q), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_SETUP_Q_VER  PFVF_OP_VER_MAX(setup_q_req_sz)

static const msg_sz_t set_q_filters_req_sz[] = {
	{sizeof(struct vf_pf_msg_set_q_filters), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_SET_Q_FILTERS_VER  PFVF_OP_VER_MAX(set_q_filters_req_sz)

static const msg_sz_t activate_q_req_sz[] = {
	{sizeof(struct vf_pf_msg_q_op), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_ACTIVATE_Q_VER  PFVF_OP_VER_MAX(activate_q_req_sz)

static const msg_sz_t deactivate_q_req_sz[] = {
	{sizeof(struct vf_pf_msg_q_op), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_DEACTIVATE_Q_VER  PFVF_OP_VER_MAX(deactivate_q_req_sz)

static const msg_sz_t teardown_q_req_sz[] = {
	{sizeof(struct vf_pf_msg_q_op), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_TEARDOWN_Q_VER  PFVF_OP_VER_MAX(teardown_q_req_sz)

static const msg_sz_t close_vf_req_sz[] = {
	{sizeof(struct vf_pf_msg_close_vf), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_CLOSE_VF_VER  PFVF_OP_VER_MAX(close_vf_req_sz)

static const msg_sz_t release_vf_req_sz[] = {
	{sizeof(struct vf_pf_msg_release_vf), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_RELEASE_VF_VER  PFVF_OP_VER_MAX(release_vf_req_sz)

static const msg_sz_t update_rss_req_sz[] = {
	{sizeof(struct vf_pf_msg_rss), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_UPDATE_RSS_VER  PFVF_OP_VER_MAX(update_rss_req_sz)

static const msg_sz_t update_rsc_req_sz[] = {
    {sizeof(struct vf_pf_msg_rsc), sizeof(struct pf_vf_msg_resp)}
};
#define PFVF_UPDATE_RSC_VER  PFVF_OP_VER_MAX(update_rsc_req_sz)

enum {
	PFVF_OP_ACQUIRE = 0,
	PFVF_OP_INIT_VF,
	PFVF_OP_SETUP_Q,
	PFVF_OP_SET_Q_FILTERS,
	PFVF_OP_ACTIVATE_Q,
	PFVF_OP_DEACTIVATE_Q,
	PFVF_OP_TEARDOWN_Q,
	PFVF_OP_CLOSE_VF,
	PFVF_OP_RELEASE_VF,
	PFVF_OP_UPDATE_RSS,
    PFVF_OP_UPDATE_RSC,
	PFVF_OP_MAX
};


/** To get size of message of the type X(request or response)
 *  for the op_code Y of the version Z one should use
 *
 *  op_code_req_sz[Y][Z].req_sz/resp_sz
 ******************************************************************/
/* const msg_sz_t* op_codes_req_sz[] = {
	(const msg_sz_t*)acquire_req_sz,
	(const msg_sz_t*)init_vf_req_sz,
	(const msg_sz_t*)setup_q_req_sz,
	(const msg_sz_t*)set_q_filters_req_sz,
	(const msg_sz_t*)activate_q_req_sz,
	(const msg_sz_t*)deactivate_q_req_sz,
	(const msg_sz_t*)teardown_q_req_sz,
	(const msg_sz_t*)close_vf_req_sz,
	(const msg_sz_t*)release_vf_req_sz
}; */

#endif /* VF_PF_SW_IF_H */
