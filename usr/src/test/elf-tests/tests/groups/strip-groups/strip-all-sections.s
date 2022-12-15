	/*
	 * Note that these sections must not be SHF_ALLOC so that we _do_
	 * strip them.
	 */

	/* object */
	.section	.debug_data,"G",@progbits,group1,comdat
	.string "DATADATADATA"

	/* text */
	.section	.debug_code,"G",@progbits,group1,comdat
	ret

	/* debug stuff */
	.section	.debug_stuff,"G",@progbits,group1,comdat
	.string "DEBUG STUFF!"
