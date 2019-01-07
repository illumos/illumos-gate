static void fn(void)
{
	static int i, *ptr = (void *)0;

	i = __sync_fetch_and_add(ptr, 0);
	i = __sync_fetch_and_sub(ptr, 0);
	i = __sync_fetch_and_or(ptr, 0);
	i = __sync_fetch_and_and(ptr, 0);
	i = __sync_fetch_and_xor(ptr, 0);
	i = __sync_fetch_and_nand(ptr, 0);
	i = __sync_add_and_fetch(ptr, 0);
	i = __sync_sub_and_fetch(ptr, 0);
	i = __sync_or_and_fetch(ptr, 0);
	i = __sync_and_and_fetch(ptr, 0);
	i = __sync_xor_and_fetch(ptr, 0);
	i = __sync_nand_and_fetch(ptr, 0);
	i = __sync_bool_compare_and_swap(ptr, 0, 1);
	i = __sync_val_compare_and_swap(ptr, 0, 1);
	__sync_synchronize();
	i = __sync_lock_test_and_set(ptr, 0);
	__sync_lock_release(ptr);
}

/*
 * check-name: __builtin_atomic
 * check-error-start
 * check-error-end
 */
