
#ifndef MAC_STATS_H
#define MAC_STATS_H


struct emac_stats {
	u32     rx_stat_ifhcinoctets;
	u32     rx_stat_ifhcinbadoctets;
	u32     rx_stat_etherstatsfragments;
	u32     rx_stat_ifhcinucastpkts;
	u32     rx_stat_ifhcinmulticastpkts;
	u32     rx_stat_ifhcinbroadcastpkts;
	u32     rx_stat_dot3statsfcserrors;
	u32     rx_stat_dot3statsalignmenterrors;
	u32     rx_stat_dot3statscarriersenseerrors;
	u32     rx_stat_xonpauseframesreceived;
	u32     rx_stat_xoffpauseframesreceived;
	u32     rx_stat_maccontrolframesreceived;
	u32     rx_stat_xoffstateentered;
	u32     rx_stat_dot3statsframestoolong;
	u32     rx_stat_etherstatsjabbers;
	u32     rx_stat_etherstatsundersizepkts;
	u32     rx_stat_etherstatspkts64octets;
	u32     rx_stat_etherstatspkts65octetsto127octets;
	u32     rx_stat_etherstatspkts128octetsto255octets;
	u32     rx_stat_etherstatspkts256octetsto511octets;
	u32     rx_stat_etherstatspkts512octetsto1023octets;
	u32     rx_stat_etherstatspkts1024octetsto1522octets;
	u32     rx_stat_etherstatspktsover1522octets;

	u32     rx_stat_falsecarriererrors;

	u32     tx_stat_ifhcoutoctets;
	u32     tx_stat_ifhcoutbadoctets;
	u32     tx_stat_etherstatscollisions;
	u32     tx_stat_outxonsent;
	u32     tx_stat_outxoffsent;
	u32     tx_stat_flowcontroldone;
	u32     tx_stat_dot3statssinglecollisionframes;
	u32     tx_stat_dot3statsmultiplecollisionframes;
	u32     tx_stat_dot3statsdeferredtransmissions;
	u32     tx_stat_dot3statsexcessivecollisions;
	u32     tx_stat_dot3statslatecollisions;
	u32     tx_stat_ifhcoutucastpkts;
	u32     tx_stat_ifhcoutmulticastpkts;
	u32     tx_stat_ifhcoutbroadcastpkts;
	u32     tx_stat_etherstatspkts64octets;
	u32     tx_stat_etherstatspkts65octetsto127octets;
	u32     tx_stat_etherstatspkts128octetsto255octets;
	u32     tx_stat_etherstatspkts256octetsto511octets;
	u32     tx_stat_etherstatspkts512octetsto1023octets;
	u32     tx_stat_etherstatspkts1024octetsto1522octets;
	u32     tx_stat_etherstatspktsover1522octets;
	u32     tx_stat_dot3statsinternalmactransmiterrors;
};


struct bmac1_stats {
	u32	tx_stat_gtpkt_lo;
	u32	tx_stat_gtpkt_hi;
	u32	tx_stat_gtxpf_lo;
	u32	tx_stat_gtxpf_hi;
	u32	tx_stat_gtfcs_lo;
	u32	tx_stat_gtfcs_hi;
	u32	tx_stat_gtmca_lo;
	u32	tx_stat_gtmca_hi;
	u32	tx_stat_gtbca_lo;
	u32	tx_stat_gtbca_hi;
	u32	tx_stat_gtfrg_lo;
	u32	tx_stat_gtfrg_hi;
	u32	tx_stat_gtovr_lo;
	u32	tx_stat_gtovr_hi;
	u32	tx_stat_gt64_lo;
	u32	tx_stat_gt64_hi;
	u32	tx_stat_gt127_lo;
	u32	tx_stat_gt127_hi;
	u32	tx_stat_gt255_lo;
	u32	tx_stat_gt255_hi;
	u32	tx_stat_gt511_lo;
	u32	tx_stat_gt511_hi;
	u32	tx_stat_gt1023_lo;
	u32	tx_stat_gt1023_hi;
	u32	tx_stat_gt1518_lo;
	u32	tx_stat_gt1518_hi;
	u32	tx_stat_gt2047_lo;
	u32	tx_stat_gt2047_hi;
	u32	tx_stat_gt4095_lo;
	u32	tx_stat_gt4095_hi;
	u32	tx_stat_gt9216_lo;
	u32	tx_stat_gt9216_hi;
	u32	tx_stat_gt16383_lo;
	u32	tx_stat_gt16383_hi;
	u32	tx_stat_gtmax_lo;
	u32	tx_stat_gtmax_hi;
	u32	tx_stat_gtufl_lo;
	u32	tx_stat_gtufl_hi;
	u32	tx_stat_gterr_lo;
	u32	tx_stat_gterr_hi;
	u32	tx_stat_gtbyt_lo;
	u32	tx_stat_gtbyt_hi;

	u32	rx_stat_gr64_lo;
	u32	rx_stat_gr64_hi;
	u32	rx_stat_gr127_lo;
	u32	rx_stat_gr127_hi;
	u32	rx_stat_gr255_lo;
	u32	rx_stat_gr255_hi;
	u32	rx_stat_gr511_lo;
	u32	rx_stat_gr511_hi;
	u32	rx_stat_gr1023_lo;
	u32	rx_stat_gr1023_hi;
	u32	rx_stat_gr1518_lo;
	u32	rx_stat_gr1518_hi;
	u32	rx_stat_gr2047_lo;
	u32	rx_stat_gr2047_hi;
	u32	rx_stat_gr4095_lo;
	u32	rx_stat_gr4095_hi;
	u32	rx_stat_gr9216_lo;
	u32	rx_stat_gr9216_hi;
	u32	rx_stat_gr16383_lo;
	u32	rx_stat_gr16383_hi;
	u32	rx_stat_grmax_lo;
	u32	rx_stat_grmax_hi;
	u32	rx_stat_grpkt_lo;
	u32	rx_stat_grpkt_hi;
	u32	rx_stat_grfcs_lo;
	u32	rx_stat_grfcs_hi;
	u32	rx_stat_grmca_lo;
	u32	rx_stat_grmca_hi;
	u32	rx_stat_grbca_lo;
	u32	rx_stat_grbca_hi;
	u32	rx_stat_grxcf_lo;
	u32	rx_stat_grxcf_hi;
	u32	rx_stat_grxpf_lo;
	u32	rx_stat_grxpf_hi;
	u32	rx_stat_grxuo_lo;
	u32	rx_stat_grxuo_hi;
	u32	rx_stat_grjbr_lo;
	u32	rx_stat_grjbr_hi;
	u32	rx_stat_grovr_lo;
	u32	rx_stat_grovr_hi;
	u32	rx_stat_grflr_lo;
	u32	rx_stat_grflr_hi;
	u32	rx_stat_grmeg_lo;
	u32	rx_stat_grmeg_hi;
	u32	rx_stat_grmeb_lo;
	u32	rx_stat_grmeb_hi;
	u32	rx_stat_grbyt_lo;
	u32	rx_stat_grbyt_hi;
	u32	rx_stat_grund_lo;
	u32	rx_stat_grund_hi;
	u32	rx_stat_grfrg_lo;
	u32	rx_stat_grfrg_hi;
	u32	rx_stat_grerb_lo;
	u32	rx_stat_grerb_hi;
	u32	rx_stat_grfre_lo;
	u32	rx_stat_grfre_hi;
	u32	rx_stat_gripj_lo;
	u32	rx_stat_gripj_hi;
};

struct bmac2_stats {
	u32	tx_stat_gtpk_lo; /* gtpok */
	u32	tx_stat_gtpk_hi; /* gtpok */
	u32	tx_stat_gtxpf_lo; /* gtpf */
	u32	tx_stat_gtxpf_hi; /* gtpf */
	u32	tx_stat_gtpp_lo; /* NEW BMAC2 */
	u32	tx_stat_gtpp_hi; /* NEW BMAC2 */
	u32	tx_stat_gtfcs_lo;
	u32	tx_stat_gtfcs_hi;
	u32	tx_stat_gtuca_lo; /* NEW BMAC2 */
	u32	tx_stat_gtuca_hi; /* NEW BMAC2 */
	u32	tx_stat_gtmca_lo;
	u32	tx_stat_gtmca_hi;
	u32	tx_stat_gtbca_lo;
	u32	tx_stat_gtbca_hi;
	u32	tx_stat_gtovr_lo;
	u32	tx_stat_gtovr_hi;
	u32	tx_stat_gtfrg_lo;
	u32	tx_stat_gtfrg_hi;
	u32	tx_stat_gtpkt1_lo; /* gtpkt */
	u32	tx_stat_gtpkt1_hi; /* gtpkt */
	u32	tx_stat_gt64_lo;
	u32	tx_stat_gt64_hi;
	u32	tx_stat_gt127_lo;
	u32	tx_stat_gt127_hi;
	u32	tx_stat_gt255_lo;
	u32	tx_stat_gt255_hi;
	u32	tx_stat_gt511_lo;
	u32	tx_stat_gt511_hi;
	u32	tx_stat_gt1023_lo;
	u32	tx_stat_gt1023_hi;
	u32	tx_stat_gt1518_lo;
	u32	tx_stat_gt1518_hi;
	u32	tx_stat_gt2047_lo;
	u32	tx_stat_gt2047_hi;
	u32	tx_stat_gt4095_lo;
	u32	tx_stat_gt4095_hi;
	u32	tx_stat_gt9216_lo;
	u32	tx_stat_gt9216_hi;
	u32	tx_stat_gt16383_lo;
	u32	tx_stat_gt16383_hi;
	u32	tx_stat_gtmax_lo;
	u32	tx_stat_gtmax_hi;
	u32	tx_stat_gtufl_lo;
	u32	tx_stat_gtufl_hi;
	u32	tx_stat_gterr_lo;
	u32	tx_stat_gterr_hi;
	u32	tx_stat_gtbyt_lo;
	u32	tx_stat_gtbyt_hi;

	u32	rx_stat_gr64_lo;
	u32	rx_stat_gr64_hi;
	u32	rx_stat_gr127_lo;
	u32	rx_stat_gr127_hi;
	u32	rx_stat_gr255_lo;
	u32	rx_stat_gr255_hi;
	u32	rx_stat_gr511_lo;
	u32	rx_stat_gr511_hi;
	u32	rx_stat_gr1023_lo;
	u32	rx_stat_gr1023_hi;
	u32	rx_stat_gr1518_lo;
	u32	rx_stat_gr1518_hi;
	u32	rx_stat_gr2047_lo;
	u32	rx_stat_gr2047_hi;
	u32	rx_stat_gr4095_lo;
	u32	rx_stat_gr4095_hi;
	u32	rx_stat_gr9216_lo;
	u32	rx_stat_gr9216_hi;
	u32	rx_stat_gr16383_lo;
	u32	rx_stat_gr16383_hi;
	u32	rx_stat_grmax_lo;
	u32	rx_stat_grmax_hi;
	u32	rx_stat_grpkt_lo;
	u32	rx_stat_grpkt_hi;
	u32	rx_stat_grfcs_lo;
	u32	rx_stat_grfcs_hi;
	u32	rx_stat_gruca_lo;
	u32	rx_stat_gruca_hi;
	u32	rx_stat_grmca_lo;
	u32	rx_stat_grmca_hi;
	u32	rx_stat_grbca_lo;
	u32	rx_stat_grbca_hi;
	u32	rx_stat_grxpf_lo; /* grpf */
	u32	rx_stat_grxpf_hi; /* grpf */
	u32	rx_stat_grpp_lo;
	u32	rx_stat_grpp_hi;
	u32	rx_stat_grxuo_lo; /* gruo */
	u32	rx_stat_grxuo_hi; /* gruo */
	u32	rx_stat_grjbr_lo;
	u32	rx_stat_grjbr_hi;
	u32	rx_stat_grovr_lo;
	u32	rx_stat_grovr_hi;
	u32	rx_stat_grxcf_lo; /* grcf */
	u32	rx_stat_grxcf_hi; /* grcf */
	u32	rx_stat_grflr_lo;
	u32	rx_stat_grflr_hi;
	u32	rx_stat_grpok_lo;
	u32	rx_stat_grpok_hi;
	u32	rx_stat_grmeg_lo;
	u32	rx_stat_grmeg_hi;
	u32	rx_stat_grmeb_lo;
	u32	rx_stat_grmeb_hi;
	u32	rx_stat_grbyt_lo;
	u32	rx_stat_grbyt_hi;
	u32	rx_stat_grund_lo;
	u32	rx_stat_grund_hi;
	u32	rx_stat_grfrg_lo;
	u32	rx_stat_grfrg_hi;
	u32	rx_stat_grerb_lo; /* grerrbyt */
	u32	rx_stat_grerb_hi; /* grerrbyt */
	u32	rx_stat_grfre_lo; /* grfrerr */
	u32	rx_stat_grfre_hi; /* grfrerr */
	u32	rx_stat_gripj_lo;
	u32	rx_stat_gripj_hi;
};

struct mstat_stats {
	struct {
		/* OTE MSTAT on E3 has a bug where this register's contents are
		 * actually tx_gtxpok + tx_gtxpf + (possibly)tx_gtxpp
		 */
		u32 tx_gtxpok_lo;
		u32 tx_gtxpok_hi;
		u32 tx_gtxpf_lo;
		u32 tx_gtxpf_hi;
		u32 tx_gtxpp_lo;
		u32 tx_gtxpp_hi;
		u32 tx_gtfcs_lo;
		u32 tx_gtfcs_hi;
		u32 tx_gtuca_lo;
		u32 tx_gtuca_hi;
		u32 tx_gtmca_lo;
		u32 tx_gtmca_hi;
		u32 tx_gtgca_lo;
		u32 tx_gtgca_hi;
		u32 tx_gtpkt_lo;
		u32 tx_gtpkt_hi;
		u32 tx_gt64_lo;
		u32 tx_gt64_hi;
		u32 tx_gt127_lo;
		u32 tx_gt127_hi;
		u32 tx_gt255_lo;
		u32 tx_gt255_hi;
		u32 tx_gt511_lo;
		u32 tx_gt511_hi;
		u32 tx_gt1023_lo;
		u32 tx_gt1023_hi;
		u32 tx_gt1518_lo;
		u32 tx_gt1518_hi;
		u32 tx_gt2047_lo;
		u32 tx_gt2047_hi;
		u32 tx_gt4095_lo;
		u32 tx_gt4095_hi;
		u32 tx_gt9216_lo;
		u32 tx_gt9216_hi;
		u32 tx_gt16383_lo;
		u32 tx_gt16383_hi;
		u32 tx_gtufl_lo;
		u32 tx_gtufl_hi;
		u32 tx_gterr_lo;
		u32 tx_gterr_hi;
		u32 tx_gtbyt_lo;
		u32 tx_gtbyt_hi;
		u32 tx_collisions_lo;
		u32 tx_collisions_hi;
		u32 tx_singlecollision_lo;
		u32 tx_singlecollision_hi;
		u32 tx_multiplecollisions_lo;
		u32 tx_multiplecollisions_hi;
		u32 tx_deferred_lo;
		u32 tx_deferred_hi;
		u32 tx_excessivecollisions_lo;
		u32 tx_excessivecollisions_hi;
		u32 tx_latecollisions_lo;
		u32 tx_latecollisions_hi;
	} stats_tx;

	struct {
		u32 rx_gr64_lo;
		u32 rx_gr64_hi;
		u32 rx_gr127_lo;
		u32 rx_gr127_hi;
		u32 rx_gr255_lo;
		u32 rx_gr255_hi;
		u32 rx_gr511_lo;
		u32 rx_gr511_hi;
		u32 rx_gr1023_lo;
		u32 rx_gr1023_hi;
		u32 rx_gr1518_lo;
		u32 rx_gr1518_hi;
		u32 rx_gr2047_lo;
		u32 rx_gr2047_hi;
		u32 rx_gr4095_lo;
		u32 rx_gr4095_hi;
		u32 rx_gr9216_lo;
		u32 rx_gr9216_hi;
		u32 rx_gr16383_lo;
		u32 rx_gr16383_hi;
		u32 rx_grpkt_lo;
		u32 rx_grpkt_hi;
		u32 rx_grfcs_lo;
		u32 rx_grfcs_hi;
		u32 rx_gruca_lo;
		u32 rx_gruca_hi;
		u32 rx_grmca_lo;
		u32 rx_grmca_hi;
		u32 rx_grbca_lo;
		u32 rx_grbca_hi;
		u32 rx_grxpf_lo;
		u32 rx_grxpf_hi;
		u32 rx_grxpp_lo;
		u32 rx_grxpp_hi;
		u32 rx_grxuo_lo;
		u32 rx_grxuo_hi;
		u32 rx_grovr_lo;
		u32 rx_grovr_hi;
		u32 rx_grxcf_lo;
		u32 rx_grxcf_hi;
		u32 rx_grflr_lo;
		u32 rx_grflr_hi;
		u32 rx_grpok_lo;
		u32 rx_grpok_hi;
		u32 rx_grbyt_lo;
		u32 rx_grbyt_hi;
		u32 rx_grund_lo;
		u32 rx_grund_hi;
		u32 rx_grfrg_lo;
		u32 rx_grfrg_hi;
		u32 rx_grerb_lo;
		u32 rx_grerb_hi;
		u32 rx_grfre_lo;
		u32 rx_grfre_hi;

		u32 rx_alignmenterrors_lo;
		u32 rx_alignmenterrors_hi;
		u32 rx_falsecarrier_lo;
		u32 rx_falsecarrier_hi;
		u32 rx_llfcmsgcnt_lo;
		u32 rx_llfcmsgcnt_hi;
	} stats_rx;
};

union mac_stats {
	struct emac_stats	emac_stats;
	struct bmac1_stats	bmac1_stats;
	struct bmac2_stats	bmac2_stats;
	struct mstat_stats	mstat_stats;
};


struct mac_stx {
	/* in_bad_octets */
	u32     rx_stat_ifhcinbadoctets_hi;
	u32     rx_stat_ifhcinbadoctets_lo;

	/* out_bad_octets */
	u32     tx_stat_ifhcoutbadoctets_hi;
	u32     tx_stat_ifhcoutbadoctets_lo;

	/* crc_receive_errors */
	u32     rx_stat_dot3statsfcserrors_hi;
	u32     rx_stat_dot3statsfcserrors_lo;
	/* alignment_errors */
	u32     rx_stat_dot3statsalignmenterrors_hi;
	u32     rx_stat_dot3statsalignmenterrors_lo;
	/* carrier_sense_errors */
	u32     rx_stat_dot3statscarriersenseerrors_hi;
	u32     rx_stat_dot3statscarriersenseerrors_lo;
	/* false_carrier_detections */
	u32     rx_stat_falsecarriererrors_hi;
	u32     rx_stat_falsecarriererrors_lo;

	/* runt_packets_received */
	u32     rx_stat_etherstatsundersizepkts_hi;
	u32     rx_stat_etherstatsundersizepkts_lo;
	/* jabber_packets_received */
	u32     rx_stat_dot3statsframestoolong_hi;
	u32     rx_stat_dot3statsframestoolong_lo;

	/* error_runt_packets_received */
	u32     rx_stat_etherstatsfragments_hi;
	u32     rx_stat_etherstatsfragments_lo;
	/* error_jabber_packets_received */
	u32     rx_stat_etherstatsjabbers_hi;
	u32     rx_stat_etherstatsjabbers_lo;

	/* control_frames_received */
	u32     rx_stat_maccontrolframesreceived_hi;
	u32     rx_stat_maccontrolframesreceived_lo;
	u32     rx_stat_mac_xpf_hi;
	u32     rx_stat_mac_xpf_lo;
	u32     rx_stat_mac_xcf_hi;
	u32     rx_stat_mac_xcf_lo;

	/* xoff_state_entered */
	u32     rx_stat_xoffstateentered_hi;
	u32     rx_stat_xoffstateentered_lo;
	/* pause_xon_frames_received */
	u32     rx_stat_xonpauseframesreceived_hi;
	u32     rx_stat_xonpauseframesreceived_lo;
	/* pause_xoff_frames_received */
	u32     rx_stat_xoffpauseframesreceived_hi;
	u32     rx_stat_xoffpauseframesreceived_lo;
	/* pause_xon_frames_transmitted */
	u32     tx_stat_outxonsent_hi;
	u32     tx_stat_outxonsent_lo;
	/* pause_xoff_frames_transmitted */
	u32     tx_stat_outxoffsent_hi;
	u32     tx_stat_outxoffsent_lo;
	/* flow_control_done */
	u32     tx_stat_flowcontroldone_hi;
	u32     tx_stat_flowcontroldone_lo;

	/* ether_stats_collisions */
	u32     tx_stat_etherstatscollisions_hi;
	u32     tx_stat_etherstatscollisions_lo;
	/* single_collision_transmit_frames */
	u32     tx_stat_dot3statssinglecollisionframes_hi;
	u32     tx_stat_dot3statssinglecollisionframes_lo;
	/* multiple_collision_transmit_frames */
	u32     tx_stat_dot3statsmultiplecollisionframes_hi;
	u32     tx_stat_dot3statsmultiplecollisionframes_lo;
	/* deferred_transmissions */
	u32     tx_stat_dot3statsdeferredtransmissions_hi;
	u32     tx_stat_dot3statsdeferredtransmissions_lo;
	/* excessive_collision_frames */
	u32     tx_stat_dot3statsexcessivecollisions_hi;
	u32     tx_stat_dot3statsexcessivecollisions_lo;
	/* late_collision_frames */
	u32     tx_stat_dot3statslatecollisions_hi;
	u32     tx_stat_dot3statslatecollisions_lo;

	/* frames_transmitted_64_bytes */
	u32     tx_stat_etherstatspkts64octets_hi;
	u32     tx_stat_etherstatspkts64octets_lo;
	/* frames_transmitted_65_127_bytes */
	u32     tx_stat_etherstatspkts65octetsto127octets_hi;
	u32     tx_stat_etherstatspkts65octetsto127octets_lo;
	/* frames_transmitted_128_255_bytes */
	u32     tx_stat_etherstatspkts128octetsto255octets_hi;
	u32     tx_stat_etherstatspkts128octetsto255octets_lo;
	/* frames_transmitted_256_511_bytes */
	u32     tx_stat_etherstatspkts256octetsto511octets_hi;
	u32     tx_stat_etherstatspkts256octetsto511octets_lo;
	/* frames_transmitted_512_1023_bytes */
	u32     tx_stat_etherstatspkts512octetsto1023octets_hi;
	u32     tx_stat_etherstatspkts512octetsto1023octets_lo;
	/* frames_transmitted_1024_1522_bytes */
	u32     tx_stat_etherstatspkts1024octetsto1522octets_hi;
	u32     tx_stat_etherstatspkts1024octetsto1522octets_lo;
	/* frames_transmitted_1523_9022_bytes */
	u32     tx_stat_etherstatspktsover1522octets_hi;
	u32     tx_stat_etherstatspktsover1522octets_lo;
	u32     tx_stat_mac_2047_hi;
	u32     tx_stat_mac_2047_lo;
	u32     tx_stat_mac_4095_hi;
	u32     tx_stat_mac_4095_lo;
	u32     tx_stat_mac_9216_hi;
	u32     tx_stat_mac_9216_lo;
	u32     tx_stat_mac_16383_hi;
	u32     tx_stat_mac_16383_lo;

	/* internal_mac_transmit_errors */
	u32     tx_stat_dot3statsinternalmactransmiterrors_hi;
	u32     tx_stat_dot3statsinternalmactransmiterrors_lo;

	/* if_out_discards */
	u32     tx_stat_mac_ufl_hi;
	u32     tx_stat_mac_ufl_lo;
};


#define MAC_STX_IDX_MAX                     2

struct host_port_stats {
	u32            host_port_stats_counter;

	struct mac_stx mac_stx[MAC_STX_IDX_MAX];

	u32            brb_drop_hi;
	u32            brb_drop_lo;

	u32            not_used; /* obsolete as of MFW 7.2.1 */

	u32            pfc_frames_tx_hi;
	u32            pfc_frames_tx_lo;
	u32            pfc_frames_rx_hi;
	u32            pfc_frames_rx_lo;

	u32            eee_lpi_count_hi;
	u32            eee_lpi_count_lo;
};


struct host_func_stats {
	u32     host_func_stats_start;

	u32     total_bytes_received_hi;
	u32     total_bytes_received_lo;

	u32     total_bytes_transmitted_hi;
	u32     total_bytes_transmitted_lo;

	u32     total_unicast_packets_received_hi;
	u32     total_unicast_packets_received_lo;

	u32     total_multicast_packets_received_hi;
	u32     total_multicast_packets_received_lo;

	u32     total_broadcast_packets_received_hi;
	u32     total_broadcast_packets_received_lo;

	u32     total_unicast_packets_transmitted_hi;
	u32     total_unicast_packets_transmitted_lo;

	u32     total_multicast_packets_transmitted_hi;
	u32     total_multicast_packets_transmitted_lo;

	u32     total_broadcast_packets_transmitted_hi;
	u32     total_broadcast_packets_transmitted_lo;

	u32     valid_bytes_received_hi;
	u32     valid_bytes_received_lo;

	u32     host_func_stats_end;
};

/* VIC definitions */
#define VICSTATST_UIF_INDEX 2

/*
 * stats collected for afex.
 * NOTE: structure is exactly as expected to be received by the switch.
 *       order must remain exactly as is unless protocol changes !
 */
struct afex_stats {
	u32 tx_unicast_frames_hi;
	u32 tx_unicast_frames_lo;
	u32 tx_unicast_bytes_hi;
	u32 tx_unicast_bytes_lo;
	u32 tx_multicast_frames_hi;
	u32 tx_multicast_frames_lo;
	u32 tx_multicast_bytes_hi;
	u32 tx_multicast_bytes_lo;
	u32 tx_broadcast_frames_hi;
	u32 tx_broadcast_frames_lo;
	u32 tx_broadcast_bytes_hi;
	u32 tx_broadcast_bytes_lo;
	u32 tx_frames_discarded_hi;
	u32 tx_frames_discarded_lo;
	u32 tx_frames_dropped_hi;
	u32 tx_frames_dropped_lo;

	u32 rx_unicast_frames_hi;
	u32 rx_unicast_frames_lo;
	u32 rx_unicast_bytes_hi;
	u32 rx_unicast_bytes_lo;
	u32 rx_multicast_frames_hi;
	u32 rx_multicast_frames_lo;
	u32 rx_multicast_bytes_hi;
	u32 rx_multicast_bytes_lo;
	u32 rx_broadcast_frames_hi;
	u32 rx_broadcast_frames_lo;
	u32 rx_broadcast_bytes_hi;
	u32 rx_broadcast_bytes_lo;
	u32 rx_frames_discarded_hi;
	u32 rx_frames_discarded_lo;
	u32 rx_frames_dropped_hi;
	u32 rx_frames_dropped_lo;
};

/* To maintain backward compatibility between FW and drivers, new elements */
/* should be added to the end of the structure. */

/* Per  Port Statistics    */
struct port_info {
	u32 size; /* size of this structure (i.e. sizeof(port_info))  */
	u32 enabled;      /* 0 =Disabled, 1= Enabled */
	u32 link_speed;   /* multiplier of 100Mb */
	u32 wol_support;  /* WoL Support (i.e. Non-Zero if WOL supported ) */
	u32 flow_control; /* 802.3X Flow Ctrl. 0=off 1=RX 2=TX 3=RX&TX.*/
	u32 flex10;     /* Flex10 mode enabled. non zero = yes */
	u32 rx_drops;  /* RX Discards. Counters roll over, never reset */
	u32 rx_errors; /* RX Errors. Physical Port Stats L95, All PFs and NC-SI.
				   This is flagged by Consumer as an error. */
	u32 rx_uncast_lo;   /* RX Unicast Packets. Free running counters: */
	u32 rx_uncast_hi;   /* RX Unicast Packets. Free running counters: */
	u32 rx_mcast_lo;    /* RX Multicast Packets  */
	u32 rx_mcast_hi;    /* RX Multicast Packets  */
	u32 rx_bcast_lo;    /* RX Broadcast Packets  */
	u32 rx_bcast_hi;    /* RX Broadcast Packets  */
	u32 tx_uncast_lo;   /* TX Unicast Packets   */
	u32 tx_uncast_hi;   /* TX Unicast Packets   */
	u32 tx_mcast_lo;    /* TX Multicast Packets  */
	u32 tx_mcast_hi;    /* TX Multicast Packets  */
	u32 tx_bcast_lo;    /* TX Broadcast Packets  */
	u32 tx_bcast_hi;    /* TX Broadcast Packets  */
	u32 tx_errors;      /* TX Errors              */
	u32 tx_discards;    /* TX Discards          */
	u32 rx_frames_lo;   /* RX Frames received  */
	u32 rx_frames_hi;   /* RX Frames received  */
	u32 rx_bytes_lo;    /* RX Bytes received    */
	u32 rx_bytes_hi;    /* RX Bytes received    */
	u32 tx_frames_lo;   /* TX Frames sent      */
	u32 tx_frames_hi;   /* TX Frames sent      */
	u32 tx_bytes_lo;    /* TX Bytes sent        */
	u32 tx_bytes_hi;    /* TX Bytes sent        */
	u32 link_status;  /* Port P Link Status. 1:0 bit for port enabled.
				1:1 bit for link good,
				2:1 Set if link changed between last poll. */
	u32 tx_pfc_frames_lo;   /* PFC Frames sent.    */
	u32 tx_pfc_frames_hi;   /* PFC Frames sent.    */
	u32 rx_pfc_frames_lo;   /* PFC Frames Received. */
	u32 rx_pfc_frames_hi;   /* PFC Frames Received. */
};

#endif /* MAC_STATS_H */

