	/* object */
	.section	.test_data,"aG",@progbits,group1,comdat
	.string "DATADATADATA"

	/* debug stuff */
	.section	.debug_stuff,"G",@progbits,group1,comdat
	.string "DEBUG STUFF!"

	/* debug stuff */
	.section	.debug_stuff2,"G",@progbits,group1,comdat
	.string "DEBUG STUFF!"

	/* text */
	.section	.test_code,"aG",@progbits,group1,comdat
	ret
