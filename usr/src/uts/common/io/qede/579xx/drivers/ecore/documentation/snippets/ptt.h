/*
 * @brief ecore_ptt_acquire - Allocate a PTT window
 *
 * Should be called at the entry point to the driver (at the beginning of an
 * exported function)
 *
 * @param p_hwfn
 *
 * @return struct ecore_ptt
 */
struct ecore_ptt *ecore_ptt_acquire(struct ecore_hwfn   *p_hwfn);

/*
 * @brief ecore_ptt_release - Release PTT Window
 *
 * Should be called at the end of a flow - at the end of the function that
 * acquired the PTT.
 *
 * @param p_hwfn
 * @param p_ptt
 */
void ecore_ptt_release(struct ecore_hwfn    *p_hwfn,
               struct ecore_ptt     *p_ptt);

/*
 * @brief ecore_wr - Write value to GRC BAR using the given ptt
 *
 * @param p_hwfn
 * @param p_ptt
 * @param val
 * @param hw_addr
 */
void ecore_wr(struct ecore_hwfn *p_hwfn,
          struct ecore_ptt  *p_ptt,
          u32       hw_addr,
          u32       val);

/*
 * @brief ecore_rd - Read value to GRC BAR using the given ptt
 *
 * @param p_hwfn
 * @param p_ptt
 * @param val
 * @param hw_addr
 */
u32 ecore_rd(struct ecore_hwfn  *p_hwfn,
         struct ecore_ptt   *p_ptt,
         u32        hw_addr);

/*
 * @brief ecore_ptt_pretend - pretend to be another function
 *        when accessing the ptt window
 *
 * @param p_hwfn
 * @param p_ptt
 * @param pretend
 */
void ecore_ptt_pretend(struct ecore_hwfn    *p_hwfn,
               struct ecore_ptt     *p_ptt,
               struct pxp_pretend   pretend);
