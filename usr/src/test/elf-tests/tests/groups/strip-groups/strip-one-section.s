	/* object */
	.section	.test_data,"aG",@progbits,group1,comdat
	.string "DATADATADATA"

	/* text */
	.section	.test_code,"aG",@progbits,group1,comdat
	ret

	/* debug stuff */
	.section	.debug_stuff,"G",@progbits,group1,comdat
	.string "DEBUG STUFF!"
