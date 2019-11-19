/* Compatibility framework for ipchains and ipfwadm support; designed
   to look as much like the 2.2 infrastructure as possible. */
struct notifier_block;

#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/icmp.h>
#include <linux/if.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <net/ip.h>
#include <net/route.h>
#include "compat_firewall.h"
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>

/* Theoretically, we could one day use 2.4 helpers, but for now it
   just confuses depmod --RR */
/* EXPORT_NO_SYMBOLS; */

static struct firewall_ops *fwops;

/* They call these; we do what they want. */
int ipsm_register_firewall(int pf, struct firewall_ops *fw)
{
	if (pf != PF_INET) {
		printk("Attempt to register non-IP firewall module.\n");
		return -EINVAL;
	}
	if (fwops) {
		printk("Attempt to register multiple firewall modules.\n");
		return -EBUSY;
	}

	fwops = fw;
	return 0;
}

int ipsm_unregister_firewall(int pf, struct firewall_ops *fw)
{
	fwops = NULL;
	return 0;
}

static unsigned int
fw_in(unsigned int hooknum,
      struct sk_buff **pskb,
      const struct net_device *in,
      const struct net_device *out,
      int (*okfn)(struct sk_buff *))
{
	int ret = FW_BLOCK;
	u_int16_t redirpt;

	/* Assume worse case: any hook could change packet */
	/* (*pskb)->nfcache |= NFC_UNKNOWN | NFC_ALTERED; */
	if ((*pskb)->ip_summed == CHECKSUM_HW)
		(*pskb)->ip_summed = CHECKSUM_NONE;

	/* Firewall rules can alter TOS: raw socket (tcpdump) may have
           clone of incoming skb: don't disturb it --RR */
	if (skb_cloned(*pskb) && !(*pskb)->sk) {
		struct sk_buff *nskb = skb_copy(*pskb, GFP_ATOMIC);
		if (!nskb)
			return NF_DROP;
		kfree_skb(*pskb);
		*pskb = nskb;
	}

	switch (hooknum) {
	case NF_IP_PRE_ROUTING:
		if ((*pskb)->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
		  printk("!!(*pskb)->nh.iph->frag_off & htons()!!\n"); /*** DDD **/
		}

		ret = fwops->fw_input(fwops, PF_INET, (struct net_device *)in,
				      &redirpt, pskb);
		break;
	}

	switch (ret) {
	case FW_REJECT: {
		/* Alexey says:
		 *
		 * Generally, routing is THE FIRST thing to make, when
		 * packet enters IP stack. Before packet is routed you
		 * cannot call any service routines from IP stack.  */
		struct iphdr *iph = (*pskb)->nh.iph;

		if ((*pskb)->dst != NULL
		    || ip_route_input(*pskb, iph->daddr, iph->saddr, iph->tos,
				      (struct net_device *)in) == 0)
			icmp_send(*pskb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH,
				  0);
		return NF_DROP;
	}

	case FW_ACCEPT:
	case FW_SKIP:
		return NF_ACCEPT;
	default:
		/* FW_BLOCK */
		return NF_DROP;
	}
}

extern int ipsm_ctl(int optval, void *m, unsigned int len);

static struct nf_hook_ops preroute_ops = {
        .hook           = fw_in,
        .owner          = THIS_MODULE,
        .pf             = PF_INET,
        .hooknum        = NF_IP_PRE_ROUTING,
	/* .priority    = NF_IP_PRI_FILTER, */
        .priority       = NF_IP_PRI_CONNTRACK-20,
};

extern int ipsm_init_or_cleanup(int init);

static int init_or_cleanup(int init)
{
	int ret = 0;

	if (!init) goto cleanup;

	if (ret < 0)
		goto cleanup_nothing;

	ret = ipsm_init_or_cleanup(1);
	if (ret < 0)
		goto cleanup_sockopt;

	if (ret < 0)
		goto cleanup_ipsm;

	nf_register_hook(&preroute_ops);

	return ret;

 cleanup:
	nf_unregister_hook(&preroute_ops);

 cleanup_ipsm:
	ipsm_init_or_cleanup(0);

 cleanup_sockopt:

 cleanup_nothing:
	return ret;
}

static int __init init(void)
{
	return init_or_cleanup(1);
}

static void __exit fini(void)
{
	init_or_cleanup(0);
}

MODULE_LICENSE("GPL");
module_init(init);
module_exit(fini);
