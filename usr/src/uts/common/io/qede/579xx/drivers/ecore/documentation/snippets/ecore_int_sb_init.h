/*
 * @brief ecore_int_sb_init - Initializes the sb_info structure.
 *
 * once the structure is initialized it can be passed to sb related functions.
 *
 * @param p_hwfn
 * @param p_ptt
 * @param sb_info   points to an uninitialized (but
 *          allocated) sb_info structure
 * @param sb_virt_addr
 * @param sb_phy_addr
 * @param sb_id     the sb_id to be used (zero based in driver)
 *          should use ECORE_SP_SB_ID for SP Status block
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_int_sb_init(struct ecore_hwfn	*p_hwfn,
		                       struct ecore_ptt		*p_ptt,
		                       struct ecore_sb_info	*sb_info,
		                       void			*sb_virt_addr,
		                       dma_addr_t		sb_phy_addr,
		                       u16			sb_id);
