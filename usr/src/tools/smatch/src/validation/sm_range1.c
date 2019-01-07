struct ture {
	int x;
};

struct ture *p;	
struct ture *q;
int xxx;

int func (void)
{

	for (xxx = 0; xxx < 10; xxx++) {
		if (p && q)
			break;	
	}
// this needs two pass processing to work.
//	if (xxx == 5)
//		q->x = 1;
	if (xxx == 10)
		return;
	p->x = 1;

	return 0;
}

/*
 * check-name: Implied Ranges #1
 * check-command: smatch sm_range1.c
 */
