	/* object */
	.section	.debug_data,"aG",@progbits,group1,comdat
	.string "DATADATADATA"

	/* text */
	.section	.debug_code,"aG",@progbits,group1,comdat
	.text
	.globl text
text:
	.type text, @function
	ret
	.size text, [.-text]

	/* debug stuff */
	.section	.debug_stuff,"G",@progbits,group1,comdat
	.string "DEBUG STUFF!"
