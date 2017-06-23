/*
 *
 * @brief ecore_int_igu_enable_int - enable device interrupts
 *
 * @param p_hwfn
 * @param p_ptt
 */
void ecore_int_igu_enable_int(struct ecore_hwfn *p_hwfn,
                  struct ecore_ptt *p_ptt);

/*
 *
 * @brief ecore_int_igu_disable_int - disable device interrupts
 *
 * @param p_hwfn
 * @param p_ptt
 */
void ecore_int_igu_disable_int(struct ecore_hwfn *p_hwfn,
                   struct ecore_ptt *p_ptt);
