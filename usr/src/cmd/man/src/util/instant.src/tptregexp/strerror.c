
/* standin for strerror(3) which is missing on some systems
 * (eg, SUN)
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

char *
strerror(int num)
{
	perror(num);
	return "";
}    
