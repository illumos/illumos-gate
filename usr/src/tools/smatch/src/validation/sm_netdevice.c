
void kfree(void *);

struct net_device {
	char *name;
};

void func(void)
{
	struct net_device dev;
	struct net_device *dev2 = &dev;
	struct net_device **dev3 = &dev2;
	struct net_device *deva[10];
	struct net_device **devb[10];
	struct net_device ***devc = devb;

	kfree(dev2);
	kfree(dev3);
	kfree(deva[0]);
	kfree(devb[0]);
	kfree(devc[0]);
}
/*
 * check-name: free_netdev() vs kfree()
 * check-command: smatch -p=kernel sm_netdevice.c
 *
 * check-output-start
sm_netdevice.c:17 func() error: use free_netdev() here instead of kfree(dev2)
sm_netdevice.c:19 func() error: use free_netdev() here instead of kfree(deva[0])
 * check-output-end
 */
