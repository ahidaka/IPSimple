/* Minor modifications to fit on compatibility framework:
   Rusty.Russell@rustcorp.com.au
*/
/* #define DEBUG_IP_FIREWALL 1 */
#include <linux/config.h>
#define CONFIG_IP_FIREWALL
#if defined(CONFIG_NETLINK_DEV) || defined(CONFIG_NETLINK_DEV_MODULE)
#define CONFIG_IP_FIREWALL_NETLINK
#endif

/*
 *	IP firewalling code. This is taken from 4.4BSD. Please note the
 *	copyright message below. As per the GPL it must be maintained
 *	and the licenses thus do not conflict. While this port is subject
 *	to the GPL I also place my modifications under the original
 *	license in recognition of the original copyright.
 *				-- Alan Cox.
 *
 *	$Id: ipfwadm_core.c,v 1.9.2.2 2002/01/24 15:50:42 davem Exp $
 *
 *	Ported from BSD to Linux,
 *		Alan Cox 22/Nov/1994.
 *	Zeroing /proc and other additions
 *		Jos Vos 4/Feb/1995.
 *	Merged and included the FreeBSD-Current changes at Ugen's request
 *	(but hey it's a lot cleaner now). Ugen would prefer in some ways
 *	we waited for his final product but since Linux 1.2.0 is about to
 *	appear it's not practical - Read: It works, it's not clean but please
 *	don't consider it to be his standard of finished work.
 *		Alan Cox 12/Feb/1995
 *	Porting bidirectional entries from BSD, fixing accounting issues,
 *	adding struct ip_fwpkt for checking packets with interface address
 *		Jos Vos 5/Mar/1995.
 *	Established connections (ACK check), ACK check on bidirectional rules,
 *	ICMP type check.
 *		Wilfred Mollenvanger 7/7/1995.
 *	TCP attack protection.
 *		Alan Cox 25/8/95, based on information from bugtraq.
 *	ICMP type printk, IP_FW_F_APPEND
 *		Bernd Eckenfels 1996-01-31
 *	Split blocking chain into input and output chains, add new "insert" and
 *	"append" commands to replace semi-intelligent "add" command, let "delete".
 *	only delete the first matching entry, use 0xFFFF (0xFF) as ports (ICMP
 *	types) when counting packets being 2nd and further fragments.
 *		Jos Vos <jos@xos.nl> 8/2/1996.
 *	Add support for matching on device names.
 *		Jos Vos <jos@xos.nl> 15/2/1996.
 *	Transparent proxying support.
 *		Willy Konynenberg <willy@xos.nl> 10/5/96.
 *	Make separate accounting on incoming and outgoing packets possible.
 *		Jos Vos <jos@xos.nl> 18/5/1996.
 *	Added trap out of bad frames.
 *		Alan Cox <alan@cymru.net> 17/11/1996
 *
 *
 * Masquerading functionality
 *
 * Copyright (c) 1994 Pauline Middelink
 *
 * The pieces which added masquerading functionality are totally
 * my responsibility and have nothing to with the original authors
 * copyright or doing.
 *
 * Parts distributed under GPL.
 *
 * Fixes:
 *	Pauline Middelink	:	Added masquerading.
 *	Alan Cox		:	Fixed an error in the merge.
 *	Thomas Quinot		:	Fixed port spoofing.
 *	Alan Cox		:	Cleaned up retransmits in spoofing.
 *	Alan Cox		:	Cleaned up length setting.
 *	Wouter Gadeyne		:	Fixed masquerading support of ftp PORT commands
 *
 *	Juan Jose Ciarlante	:	Masquerading code moved to ip_masq.c
 *	Andi Kleen :		Print frag_offsets and the ip flags properly.
 *
 *	All the real work was done by .....
 *
 */


/*
 * Copyright (c) 1993 Daniel Boulet
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/page.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/icmp.h>
#include <linux/netlink.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include "compat_firewall.h"
#include "ipsimple_core.h"
/* #include <linux/netfilter_ipv4/lockhelp.h> */
#include <linux/netfilter_ipv4/ip_nat_core.h>

#include <net/checksum.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/version.h>
/* #include <linux/tqueue.h> */

/*
 *	Implement IP packet firewall
 */

#ifdef DEBUG_IP_FIREWALL
#define dprintf1(a)		printk(a)
#define dprintf2(a1,a2)		printk(a1,a2)
#define dprintf3(a1,a2,a3)	printk(a1,a2,a3)
#define dprintf4(a1,a2,a3,a4)	printk(a1,a2,a3,a4)
#else
#define dprintf1(a)
#define dprintf2(a1,a2)
#define dprintf3(a1,a2,a3)
#define dprintf4(a1,a2,a3,a4)
#endif

#define print_ip(a)	 printk("%u.%u.%u.%u", NIPQUAD(a));

#ifdef DEBUG_IP_FIREWALL
#define dprint_ip(a)	print_ip(a)
#else
#define dprint_ip(a)
#endif

/* static DECLARE_RWLOCK(ip_fw_lock); */
static DEFINE_RWLOCK(ip_fw_lock);

#define WRITE_LOCK(l) write_lock_bh(l)
#define WRITE_UNLOCK(l) write_unlock_bh(l)
#define READ_LOCK(l) read_lock_bh(l)
#define	READ_UNLOCK(l) read_unlock_bh(l)

#if defined(CONFIG_IP_ACCT) || defined(CONFIG_IP_FIREWALL)

struct ip_fw *ipsm_fwd_chain;
struct ip_fw *ipsm_in_chain;
struct ip_fw *ipsm_out_chain;
struct ip_fw *ipsm_acct_chain;
struct ip_fw *ipsm_masq_chain;

static struct ip_fw **chains[] =
	{&ipsm_fwd_chain, &ipsm_in_chain, &ipsm_out_chain, &ipsm_acct_chain,
	 &ipsm_masq_chain
	};
#endif /* CONFIG_IP_ACCT || CONFIG_IP_FIREWALL */

#ifdef CONFIG_IP_FIREWALL
int ipsm_fwd_policy=IP_FW_F_ACCEPT;
int ipsm_in_policy=IP_FW_F_ACCEPT;
int ipsm_out_policy=IP_FW_F_ACCEPT;

static int *policies[] =
	{&ipsm_fwd_policy, &ipsm_in_policy, &ipsm_out_policy};

#endif

#ifdef CONFIG_IP_FIREWALL_NETLINK
/*struct sock *ipsmsk; */
#endif

/*
 *	Returns 1 if the port is matched by the vector, 0 otherwise
 */

extern inline int port_match(unsigned short *portptr,int nports,unsigned short port,int range_flag)
{
	if (!nports)
		return 1;
	if ( range_flag )
	{
		if ( portptr[0] <= port && port <= portptr[1] )
		{
			return( 1 );
		}
		nports -= 2;
		portptr += 2;
	}
	while ( nports-- > 0 )
	{
		if ( *portptr++ == port )
		{
			return( 1 );
		}
	}
	return(0);
}

#if defined(CONFIG_IP_ACCT) || defined(CONFIG_IP_FIREWALL)

/*
 *      VERY ugly piece of code which actually makes kernel printf for
 *      matching packets.
 */

#if 0
static char *chain_name(struct ip_fw *chain, int mode)
{
	if (chain == ipsm_fwd_chain)
		return "fw-fwd";
	else if (chain == ipsm_in_chain)
		return "fw-in";
	else
		return "fw-out";
}
#endif

#ifdef __DEBUG_IP_FIREWALL
static char *rule_name(struct ip_fw *f, int mode, char *buf)
{
        if(f->fw_flg&IP_FW_F_ACCEPT) {
                if(f->fw_flg&IP_FW_F_REDIR) {
                        sprintf(buf, "acc/r%d ", f->fw_pts[f->fw_nsp+f->fw_ndp]);
                        return buf;
                } else if(f->fw_flg&IP_FW_F_MASQ)
                        return "acc/masq ";
                else
                        return "acc ";
        } else if(f->fw_flg&IP_FW_F_ICMPRPL) {
                return "rej ";
        } else {
                return "deny ";
        }
}

static void print_packet(struct iphdr *ip,
                         u16 src_port, u16 dst_port, u16 icmp_type,
                         char *chain, char *rule, char *devname)
{
        __u32 *opt = (__u32 *) (ip + 1);
        int opti;
        __u16 foff = ntohs(ip->frag_off);

        printk(KERN_INFO "IP %s %s%s", chain, rule, devname);

        switch(ip->protocol)
        {
        case IPPROTO_TCP:
                printk(" TCP ");
                break;
        case IPPROTO_UDP:
                printk(" UDP ");
                break;
        case IPPROTO_ICMP:
                printk(" ICMP/%d ", icmp_type);
                break;
        default:
                printk(" PROTO=%d ", ip->protocol);
                break;
        }
        print_ip(ip->saddr);
        if(ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)
                printk(":%hu", src_port);
        printk(" ");
        print_ip(ip->daddr);
        if(ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)
                printk(":%hu", dst_port);
        printk(" L=%hu S=0x%2.2hX I=%hu FO=0x%4.4hX T=%hu",
               ntohs(ip->tot_len), ip->tos, ntohs(ip->id),
               foff & IP_OFFSET, ip->ttl);
        if (foff & IP_DF) printk(" DF=1");
        if (foff & IP_MF) printk(" MF=1");
        for (opti = 0; opti < (ip->ihl - sizeof(struct iphdr) / 4); opti++)
                printk(" O=0x%8.8X", *opt++);
        printk("\n");
}
#endif

/*
 *	Returns one of the generic firewall policies, like FW_ACCEPT.
 *	Also does accounting so you can feed it the accounting chain.
 *
 *	The modes is either IP_FW_MODE_FW (normal firewall mode),
 *	IP_FW_MODE_ACCT_IN or IP_FW_MODE_ACCT_OUT (accounting mode,
 *	steps through the entire chain and handles fragments
 *	differently), or IP_FW_MODE_CHK (handles user-level check,
 *	counters are not updated).
 */

static
int ipsm_chk(struct iphdr *ip, struct net_device *rif, __u16 *redirport,
	      struct ip_fw *chain, int policy, int mode)
{
	struct ip_fw *f;
	struct tcphdr		*tcp=(struct tcphdr *)((__u32 *)ip+ip->ihl);
	struct udphdr		*udp=(struct udphdr *)((__u32 *)ip+ip->ihl);
	struct icmphdr		*icmp=(struct icmphdr *)((__u32 *)ip+ip->ihl);
	__u32			src, dst;
	__u16			src_port=0xFFFF, dst_port=0xFFFF, icmp_type=0xFF;
	unsigned short		f_prt=0, prt;
	char			notcpsyn=0, notcpack=0, match;
	unsigned short		offset;
	int			answer;
	unsigned char		tosand, tosxor;

	/*
	 *	If the chain is empty follow policy. The BSD one
	 *	accepts anything giving you a time window while
	 *	flushing and rebuilding the tables.
	 */

	src = ip->saddr;
	dst = ip->daddr;

	/*
	 *	This way we handle fragmented packets.
	 *	we ignore all fragments but the first one
	 *	so the whole packet can't be reassembled.
	 *	This way we relay on the full info which
	 *	stored only in first packet.
	 *
	 *	Note that this theoretically allows partial packet
	 *	spoofing. Not very dangerous but paranoid people may
	 *	wish to play with this. It also allows the so called
	 *	"fragment bomb" denial of service attack on some types
	 *	of system.
	 */

	offset = ntohs(ip->frag_off) & IP_OFFSET;

	/*
	 *	Don't allow a fragment of TCP 8 bytes in. Nobody
	 *	normal causes this. Its a cracker trying to break
	 *	in by doing a flag overwrite to pass the direction
	 *	checks.
	 */

	if (offset == 1 && ip->protocol == IPPROTO_TCP)
		return FW_BLOCK;

	if (offset!=0 && !(mode & (IP_FW_MODE_ACCT_IN|IP_FW_MODE_ACCT_OUT)) &&
		(ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP ||
			ip->protocol == IPPROTO_ICMP))
		return FW_ACCEPT;

	/*
	 *	 Header fragment for TCP is too small to check the bits.
	 */

	if(ip->protocol==IPPROTO_TCP && (ip->ihl<<2)+16 > ntohs(ip->tot_len))
		return FW_BLOCK;

	/*
	 *	Too short.
	 *
	 *	But only too short for a packet with ports...
	 */

	else if((ntohs(ip->tot_len)<8+(ip->ihl<<2))&&(ip->protocol==IPPROTO_TCP || ip->protocol==IPPROTO_UDP))
		return FW_BLOCK;

	src = ip->saddr;
	dst = ip->daddr;

	/*
	 *	If we got interface from which packet came
	 *	we can use the address directly. This is unlike
	 *	4.4BSD derived systems that have an address chain
	 *	per device. We have a device per address with dummy
	 *	devices instead.
	 */

	/* dprintf1("Packet "); */ /*** DDD ***/
	switch(ip->protocol)
	{
		case IPPROTO_TCP:
			dprintf1("TCP ");
			/* ports stay 0xFFFF if it is not the first fragment */
			if (!offset) {
				src_port=ntohs(tcp->source);
				dst_port=ntohs(tcp->dest);
				if(!tcp->ack && !tcp->rst)
					/* We do NOT have ACK, value TRUE */
					notcpack=1;
				if(!tcp->syn || !notcpack)
					/* We do NOT have SYN, value TRUE */
					notcpsyn=1;
			}

#ifdef __DEBUG_IP_FIREWALL
	dprint_ip(ip->saddr);

	if (ip->protocol==IPPROTO_TCP || ip->protocol==IPPROTO_UDP)
		/* This will print 65535 when it is not the first fragment! */
		dprintf2(":%d ", src_port);
	dprint_ip(ip->daddr);
	if (ip->protocol==IPPROTO_TCP || ip->protocol==IPPROTO_UDP)
		/* This will print 65535 when it is not the first fragment! */
		dprintf2(":%d ",dst_port);
	dprintf1("\n");
#endif

#ifdef __DEBUG_IP_FIREWALL
			/*** DDD ***/
			printk("*** %s: offset = %d, seq = %u, ack = %u\n",
			       chain_name(chain, mode),
			       offset, ntohl(tcp->seq), ntohl(tcp->ack_seq));
			/*** DDD ***/
#endif
			prt=IP_FW_F_TCP;
			break;
		case IPPROTO_UDP:
		  /* dprintf1("UDP "); *** DDD ***/
			/* ports stay 0xFFFF if it is not the first fragment */
			if (!offset) {
				src_port=ntohs(udp->source);
				dst_port=ntohs(udp->dest);
			}
			prt=IP_FW_F_UDP;
			break;
		case IPPROTO_ICMP:
			/* icmp_type stays 255 if it is not the first fragment */
			if (!offset)
				icmp_type=(__u16)(icmp->type);
			dprintf2("ICMP:%d \n",icmp_type); /*** DDD ***/
			prt=IP_FW_F_ICMP;
			break;
		default:
			dprintf2("p=%d ",ip->protocol);
			prt=IP_FW_F_ALL;
			break;
	}
#ifdef DEBUG_IP_FIREWALL /*** DDD ***/
	dprint_ip(ip->saddr);

	if (ip->protocol==IPPROTO_TCP || ip->protocol==IPPROTO_UDP)
		/* This will print 65535 when it is not the first fragment! */
		dprintf2(":%d ", src_port);
	dprint_ip(ip->daddr);
	if (ip->protocol==IPPROTO_TCP || ip->protocol==IPPROTO_UDP)
		/* This will print 65535 when it is not the first fragment! */
		dprintf2(":%d ",dst_port);
	dprintf1("\n");
#endif

	for (f=chain;f;f=f->fw_next)
	{
		/*
		 *	This is a bit simpler as we don't have to walk
		 *	an interface chain as you do in BSD - same logic
		 *	however.
		 */

		/*
		 *	Match can become 0x01 (a "normal" match was found),
		 *	0x02 (a reverse match was found), and 0x03 (the
		 *	IP addresses match in both directions).
		 *	Now we know in which direction(s) we should look
		 *	for a match for the TCP/UDP ports.  Both directions
		 *	might match (e.g., when both addresses are on the
		 *	same network for which an address/mask is given), but
		 *	the ports might only match in one direction.
		 *	This was obviously wrong in the original BSD code.
		 */

#ifdef DEBUG_IP_FIREWALL
		dprintf1("chain: SRC = ");
		dprint_ip(f->fw_src.s_addr);
		dprintf1(", DST = ");
		dprint_ip(f->fw_dst.s_addr);
		dprintf1("\n");
#endif
		match = 0x00;

		if ((src&f->fw_smsk.s_addr)==f->fw_src.s_addr
		&&  (dst&f->fw_dmsk.s_addr)==f->fw_dst.s_addr)
			/* normal direction */
			match |= 0x01;

		if ((f->fw_flg & IP_FW_F_BIDIR) &&
		    (dst&f->fw_smsk.s_addr)==f->fw_src.s_addr
		&&  (src&f->fw_dmsk.s_addr)==f->fw_dst.s_addr)
			/* reverse direction */
			match |= 0x02;

		if (!match)
			continue;

		/*
		 *	Look for a VIA device match
		 */
		if(f->fw_viadev)
		{
			if(rif!=f->fw_viadev)
				continue;	/* Mismatch */
		}

		/* This looks stupid, because we scan almost static
		   list, searching for static key. However, this way seems
		   to be only reasonable way of handling fw_via rules
		   (btw bsd makes the same thing).

		   It will not affect performance if you will follow
		   the following simple rules:

		   - if inteface is aliased, ALWAYS specify fw_viadev,
		     so that previous check will guarantee, that we will
		     not waste time when packet arrive on another interface.

		   - avoid using fw_via.s_addr if fw_via.s_addr is owned
		     by an aliased interface.

		                                                       --ANK
		 */
		if (f->fw_via.s_addr && rif) {
			struct in_ifaddr *ifa;

			if (rif->ip_ptr == NULL)
				continue;	/* Mismatch */

			for (ifa = ((struct in_device*)(rif->ip_ptr))->ifa_list;
			     ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_local == f->fw_via.s_addr)
					goto ifa_ok;
			}
			continue;	/* Mismatch */

		ifa_ok:;
		}

		/*
		 *	Ok the chain addresses match.
		 */

		/*
		 * For all non-TCP packets and/or non-first fragments,
		 * notcpsyn and notcpack will always be FALSE,
		 * so the IP_FW_F_TCPSYN and IP_FW_F_TCPACK flags
		 * are actually ignored for these packets.
		 */

		if((f->fw_flg&IP_FW_F_TCPSYN) && notcpsyn)
		 	continue;

		if((f->fw_flg&IP_FW_F_TCPACK) && notcpack)
		 	continue;

		f_prt=f->fw_flg&IP_FW_F_KIND;
		if (f_prt!=IP_FW_F_ALL) 
		{
			/*
			 *	Specific firewall - packet's protocol
			 *	must match firewall's.
			 */

			if(prt!=f_prt)
				continue;

			if((prt==IP_FW_F_ICMP &&
				! port_match(&f->fw_pts[0], f->fw_nsp,
					icmp_type,f->fw_flg&IP_FW_F_SRNG)) ||
			    !(prt==IP_FW_F_ICMP || ((match & 0x01) &&
				port_match(&f->fw_pts[0], f->fw_nsp, src_port,
					f->fw_flg&IP_FW_F_SRNG) &&
				port_match(&f->fw_pts[f->fw_nsp], f->fw_ndp, dst_port,
					f->fw_flg&IP_FW_F_DRNG)) || ((match & 0x02) &&
				port_match(&f->fw_pts[0], f->fw_nsp, dst_port,
					f->fw_flg&IP_FW_F_SRNG) &&
				port_match(&f->fw_pts[f->fw_nsp], f->fw_ndp, src_port,
					f->fw_flg&IP_FW_F_DRNG))))
			{
				continue;
			}
		}

		if (mode != IP_FW_MODE_CHK) {
			f->fw_bcnt+=ntohs(ip->tot_len);
			f->fw_pcnt++;
		}
		if (!(mode & (IP_FW_MODE_ACCT_IN|IP_FW_MODE_ACCT_OUT)))
			break;
	} /* Loop */

	if (!(mode & (IP_FW_MODE_ACCT_IN|IP_FW_MODE_ACCT_OUT))) {

		/*
		 * We rely on policy defined in the rejecting entry or, if no match
		 * was found, we rely on the general policy variable for this type
		 * of firewall.
		 */

		if (f!=NULL) {
			policy=f->fw_flg;
			tosand=f->fw_tosand;
			tosxor=f->fw_tosxor;
		} else {
			tosand=0xFF;
			tosxor=0x00;
		}

		if (policy&IP_FW_F_ACCEPT) {
			/* Adjust priority and recompute checksum */
			__u8 old_tos = ip->tos;
			ip->tos = (old_tos & tosand) ^ tosxor;
			if (ip->tos != old_tos)
		 		ip_send_check(ip);

				answer = FW_ACCEPT;

		} else if(policy&IP_FW_F_ICMPRPL)
			answer = FW_REJECT;
		else
			answer = FW_BLOCK;
#if 0
		printk("!(mode&(IP_FW_MODE_... policy = %d, tosand = %d, tosxor = %d, answer = %d\n",
		       policy, 
		       tosand,
		       tosxor,
		       answer); /*** DDD ***/
#endif
		return answer;
	} else
	  {
		/* we're doing accounting, always ok */
		printk("/* we're doing accounting, always ok */\n");
		return 0;
	  }
}


static void zero_fw_chain(struct ip_fw *chainptr)
{
	struct ip_fw *ctmp=chainptr;
        WRITE_LOCK(&ip_fw_lock);
	while(ctmp)
	{
		ctmp->fw_pcnt=0L;
		ctmp->fw_bcnt=0L;
		ctmp=ctmp->fw_next;
	}
        WRITE_UNLOCK(&ip_fw_lock);
}

static void free_fw_chain(struct ip_fw *volatile* chainptr)
{
        WRITE_LOCK(&ip_fw_lock);
	while ( *chainptr != NULL )
	{
		struct ip_fw *ftmp;
		ftmp = *chainptr;
		*chainptr = ftmp->fw_next;
		kfree(ftmp);
	}
        WRITE_UNLOCK(&ip_fw_lock);
}

/*** DDD ***/
static void
print_fw(struct ip_fw *p)
{
#ifdef DEBUG_IP_FIREWALL
  long i;

  printk("*fw_chain: src = %08x, dst = %08x, via = %08x, flg = %04x, nsp = %04x, ndp = %04x\n",
	 p->fw_src.s_addr,
	 p->fw_dst.s_addr,
	 p->fw_via.s_addr,
	 p->fw_flg,
	 p->fw_nsp,
	 p->fw_ndp);

  if ((i = (long) p->fw_viadev) != 0 && i != -1)
    printk("*      : viadev.name = %s, vianame = %s\n",
	   p->fw_viadev->name ? p->fw_viadev->name : "(null)",
	   p->fw_vianame ? p->fw_vianame : "(null)");
#endif
}
/*** DDD ***/


/* Volatiles to keep some of the compiler versions amused */

static int insert_in_chain(struct ip_fw *volatile* chainptr, struct ip_fw *frwl,int len)
{
	struct ip_fw *ftmp;

	ftmp = kmalloc( sizeof(struct ip_fw), GFP_ATOMIC );
	if ( ftmp == NULL )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("ipsm_ctl:  malloc said no\n");
#endif
		return( ENOMEM );
	}

	memcpy(ftmp, frwl, len);
	/*
	 *	Allow the more recent "minimise cost" flag to be
	 *	set. [Rob van Nieuwkerk]
	 */
	ftmp->fw_tosand |= 0x01;
	ftmp->fw_tosxor &= 0xFE;
	ftmp->fw_pcnt=0L;
	ftmp->fw_bcnt=0L;

        WRITE_LOCK(&ip_fw_lock);

	if ((ftmp->fw_vianame)[0]) {
		if (!(ftmp->fw_viadev = dev_get_by_name(ftmp->fw_vianame)))
			ftmp->fw_viadev = (struct net_device *) -1;
	} else
		ftmp->fw_viadev = NULL;

	ftmp->fw_next = *chainptr;
       	*chainptr=ftmp;
        WRITE_UNLOCK(&ip_fw_lock);

	/*** DDD ***/
	print_fw(ftmp);

	return(0);
}

static int append_to_chain(struct ip_fw *volatile* chainptr, struct ip_fw *frwl,int len)
{
	struct ip_fw *ftmp;
	struct ip_fw *chtmp=NULL;
	struct ip_fw *volatile chtmp_prev=NULL;

	ftmp = kmalloc( sizeof(struct ip_fw), GFP_ATOMIC );
	if ( ftmp == NULL )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("ipsm_ctl:  malloc said no\n");
#endif
		return( ENOMEM );
	}

	memcpy(ftmp, frwl, len);
	/*
	 *	Allow the more recent "minimise cost" flag to be
	 *	set. [Rob van Nieuwkerk]
	 */
	ftmp->fw_tosand |= 0x01;
	ftmp->fw_tosxor &= 0xFE;
	ftmp->fw_pcnt=0L;
	ftmp->fw_bcnt=0L;

	ftmp->fw_next = NULL;

        WRITE_LOCK(&ip_fw_lock);

	if ((ftmp->fw_vianame)[0]) {
		if (!(ftmp->fw_viadev = dev_get_by_name(ftmp->fw_vianame)))
			ftmp->fw_viadev = (struct net_device *) -1;
	} else
		ftmp->fw_viadev = NULL;

	chtmp_prev=NULL;
	for (chtmp=*chainptr;chtmp!=NULL;chtmp=chtmp->fw_next)
		chtmp_prev=chtmp;

	if (chtmp_prev)
		chtmp_prev->fw_next=ftmp;
	else
        	*chainptr=ftmp;
        WRITE_UNLOCK(&ip_fw_lock);

	/*** DDD ***/
	print_fw(ftmp);

	return(0);
}

static int del_from_chain(struct ip_fw *volatile*chainptr, struct ip_fw *frwl)
{
	struct ip_fw 	*ftmp,*ltmp;
	unsigned short	tport1,tport2,tmpnum;
	char		matches,was_found;

        WRITE_LOCK(&ip_fw_lock);

	ftmp=*chainptr;

	if ( ftmp == NULL )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("ipsm_ctl:  chain is empty\n");
#endif
                WRITE_UNLOCK(&ip_fw_lock);
		return( EINVAL );
	}

	ltmp=NULL;
	was_found=0;

	while( !was_found && ftmp != NULL )
	{
		matches=1;
		if (ftmp->fw_src.s_addr!=frwl->fw_src.s_addr
		     ||  ftmp->fw_dst.s_addr!=frwl->fw_dst.s_addr
		     ||  ftmp->fw_smsk.s_addr!=frwl->fw_smsk.s_addr
		     ||  ftmp->fw_dmsk.s_addr!=frwl->fw_dmsk.s_addr
		     ||  ftmp->fw_via.s_addr!=frwl->fw_via.s_addr
		     ||  ftmp->fw_flg!=frwl->fw_flg)
        		matches=0;

		tport1=ftmp->fw_nsp+ftmp->fw_ndp;
		tport2=frwl->fw_nsp+frwl->fw_ndp;
		if (tport1!=tport2)
		        matches=0;
		else if (tport1!=0)
		{
			for (tmpnum=0;tmpnum < tport1 && tmpnum < IP_FW_MAX_PORTS;tmpnum++)
        		if (ftmp->fw_pts[tmpnum]!=frwl->fw_pts[tmpnum])
				matches=0;
		}
		if (strncmp(ftmp->fw_vianame, frwl->fw_vianame, IFNAMSIZ))
		        matches=0;
		if(matches)
		{
			was_found=1;
			if (ltmp)
			{
				ltmp->fw_next=ftmp->fw_next;
				kfree(ftmp);
				ftmp=ltmp->fw_next;
        		}
      			else
      			{
      				*chainptr=ftmp->fw_next;
	 			kfree(ftmp);
				ftmp=*chainptr;
			}
		}
		else
		{
			ltmp = ftmp;
			ftmp = ftmp->fw_next;
		 }
	}
        WRITE_UNLOCK(&ip_fw_lock);
	if (was_found) {
		return 0;
	} else
		return(EINVAL);
}

#endif  /* CONFIG_IP_ACCT || CONFIG_IP_FIREWALL */

struct ip_fw *check_ipsm_struct(struct ip_fw *frwl, int len)
{

	if ( len != sizeof(struct ip_fw) )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: len=%d, want %d\n",len, (int) sizeof(struct ip_fw));
#endif
		return(NULL);
	}

	if ( (frwl->fw_flg & ~IP_FW_F_MASK) != 0 )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: undefined flag bits set (flags=%x)\n",
			frwl->fw_flg);
#endif
		return(NULL);
	}

#ifndef CONFIG_IP_TRANSPARENT_PROXY
	if (frwl->fw_flg & IP_FW_F_REDIR) {
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: unsupported flag IP_FW_F_REDIR\n");
#endif
		return(NULL);
	}
#endif

#ifndef CONFIG_IP_MASQUERADE
	if (frwl->fw_flg & IP_FW_F_MASQ) {
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: unsupported flag IP_FW_F_MASQ\n");
#endif
		return(NULL);
	}
#endif

	if ( (frwl->fw_flg & IP_FW_F_SRNG) && frwl->fw_nsp < 2 )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: src range set but fw_nsp=%d\n",
			frwl->fw_nsp);
#endif
		return(NULL);
	}

	if ( (frwl->fw_flg & IP_FW_F_DRNG) && frwl->fw_ndp < 2 )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: dst range set but fw_ndp=%d\n",
			frwl->fw_ndp);
#endif
		return(NULL);
	}

	if ( frwl->fw_nsp + frwl->fw_ndp > (frwl->fw_flg & IP_FW_F_REDIR ? IP_FW_MAX_PORTS - 1 : IP_FW_MAX_PORTS) )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: too many ports (%d+%d)\n",
			frwl->fw_nsp,frwl->fw_ndp);
#endif
		return(NULL);
	}

	return frwl;
}

#ifdef CONFIG_IP_FIREWALL
static
int ipsm_ctl(int stage, void *m, int len)
{
	int cmd, fwtype;

	cmd = stage & IP_FW_COMMAND;
	fwtype = (stage & IP_FW_TYPE) >> IP_FW_SHIFT;
#ifdef DEBUG_IP_FIREWALL
	printk("ipsm_ctl: cmd = %d, fwtype = %d\n",
	       cmd, fwtype); /*** DDD ***/
#endif
	if ( cmd == IP_FW_FLUSH )
	{
		free_fw_chain(chains[fwtype]);
		return(0);
	}

	if ( cmd == IP_FW_ZERO )
	{
		zero_fw_chain(*chains[fwtype]);
		return(0);
	}

	if ( cmd == IP_FW_POLICY )
	{
		int *tmp_policy_ptr;
		tmp_policy_ptr=(int *)m;
		*policies[fwtype] = *tmp_policy_ptr;
		return 0;
	}

	if ( cmd == IP_FW_CHECK )
	{
		struct net_device *viadev;
		struct ip_fwpkt *ipsmp;
		struct iphdr *ip;

		if ( len != sizeof(struct ip_fwpkt) )
		{
#ifdef DEBUG_IP_FIREWALL
			printk("ipsm_ctl: length=%d, expected %d\n",
				len, (int) sizeof(struct ip_fwpkt));
#endif
			return( EINVAL );
		}

	 	ipsmp = (struct ip_fwpkt *)m;
	 	ip = &(ipsmp->fwp_iph);

		if ( !(viadev = dev_get_by_name(ipsmp->fwp_vianame)) ) {
#ifdef DEBUG_IP_FIREWALL
			printk("ipsm_ctl: invalid device \"%s\"\n", ipsmp->fwp_vianame);
#endif
			return(EINVAL);
		} else if ( ip->ihl != sizeof(struct iphdr) / sizeof(int)) {
#ifdef DEBUG_IP_FIREWALL
			printk("ipsm_ctl: ip->ihl=%d, want %d\n",ip->ihl,
					(int) (sizeof(struct iphdr)/sizeof(int)));
#endif
			return(EINVAL);
		}

		switch (ipsm_chk(ip, viadev, NULL, *chains[fwtype],
				*policies[fwtype], IP_FW_MODE_CHK))
		{
			case FW_ACCEPT:
				return(0);
	    		case FW_REDIRECT:
				return(ECONNABORTED);
	    		case FW_MASQUERADE:
				return(ECONNRESET);
	    		case FW_REJECT:
				return(ECONNREFUSED);
			default: /* FW_BLOCK */
				return(ETIMEDOUT);
		}
	}
/*
 *	Here we really working hard-adding new elements
 *	to blocking/forwarding chains or deleting 'em
 */

	if ( cmd == IP_FW_INSERT || cmd == IP_FW_APPEND || cmd == IP_FW_DELETE )
	{
		struct ip_fw *frwl;
		int fwtype;

		frwl=check_ipsm_struct(m,len);
		if (frwl==NULL)
			return (EINVAL);
		fwtype = (stage & IP_FW_TYPE) >> IP_FW_SHIFT;

		switch (cmd)
		{
			case IP_FW_INSERT:
				return(insert_in_chain(chains[fwtype],frwl,len));
			case IP_FW_APPEND:
				return(append_to_chain(chains[fwtype],frwl,len));
			case IP_FW_DELETE:
				return(del_from_chain(chains[fwtype],frwl));
			default:
			/*
	 		 *	Should be panic but... (Why are BSD people panic obsessed ??)
			 */
#ifdef DEBUG_IP_FIREWALL
				printk("ipsm_ctl:  unknown request %d\n",stage);
#endif
				return(EINVAL);
		}
	}

#ifdef DEBUG_IP_FIREWALL
	printk("ipsm_ctl:  unknown request %d\n",stage);
#endif
	return(ENOPROTOOPT);
}
#endif /* CONFIG_IP_FIREWALL */

#if defined(CONFIG_IP_FIREWALL) || defined(CONFIG_IP_ACCT)

static int ipsm_chain_procinfo(int stage, char *buffer, char **start,
			     off_t offset, int length, int reset)
{
	off_t pos=0, begin=0;
	struct ip_fw *i;
	int len, p;
	int last_len = 0;


	switch(stage)
	{
#ifdef CONFIG_IP_FIREWALL
		case IP_FW_IN:
			i = ipsm_in_chain;
			len=sprintf(buffer, "IP firewall input rules, default %d\n",
				ipsm_in_policy);
			break;
#endif
		default:
			/* this should never be reached, but safety first... */
			i = NULL;
			len=0;
			break;
	}

        READ_LOCK(&ip_fw_lock);

	while(i!=NULL)
	{
		len+=sprintf(buffer+len,"%08X/%08X->%08X/%08X %.16s %08X %X ",
			ntohl(i->fw_src.s_addr),ntohl(i->fw_smsk.s_addr),
			ntohl(i->fw_dst.s_addr),ntohl(i->fw_dmsk.s_addr),
			(i->fw_vianame)[0] ? i->fw_vianame : "-",
			ntohl(i->fw_via.s_addr), i->fw_flg);
		/* 10 is enough for a 32 bit box but the counters are 64bit on
		   the Alpha and Ultrapenguin */
		len+=sprintf(buffer+len,"%u %u %-20lu %-20lu",
			i->fw_nsp,i->fw_ndp, i->fw_pcnt,i->fw_bcnt);
		for (p = 0; p < IP_FW_MAX_PORTS; p++)
			len+=sprintf(buffer+len, " %u", i->fw_pts[p]);
		len+=sprintf(buffer+len, " A%02X X%02X", i->fw_tosand, i->fw_tosxor);
		buffer[len++]='\n';
		buffer[len]='\0';
		pos=begin+len;
		if(pos<offset)
		{
			len=0;
			begin=pos;
		}
		else if(pos>offset+length)
		{
			len = last_len;
			break;
		}
		else if(reset)
		{
			/* This needs to be done at this specific place! */
			i->fw_pcnt=0L;
			i->fw_bcnt=0L;
		}
		last_len = len;
		i=i->fw_next;
	}
        READ_UNLOCK(&ip_fw_lock);
	*start=buffer+(offset-begin);
	len-=(offset-begin);
	if(len>length)
		len=length;
	return len;
}
#endif

#ifdef CONFIG_IP_FIREWALL

static int ipsm_in_procinfo(char *buffer, char **start, off_t offset,
			      int length
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,29)
			     , int reset
#endif
	)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,29)
	/* FIXME: No more `atomic' read and reset.  Wonderful 8-( --RR */
	int reset = 0;
#endif
	return ipsm_chain_procinfo(IP_FW_IN, buffer,start,offset,length,
				 reset);
}
#endif


#ifdef CONFIG_IP_FIREWALL
/*
 *	Interface to the generic firewall chains.
 */

static
int ipsm_input_check(struct firewall_ops *this, int pf,
		     struct net_device *dev, void *arg,
		     struct sk_buff **pskb)
{
	return ipsm_chk((*pskb)->nh.iph, dev, arg, ipsm_in_chain, ipsm_in_policy,
			 IP_FW_MODE_FW);
}

struct firewall_ops ipsm_ops={
        .fw_input=ipsm_input_check,
};

#endif

#if defined(CONFIG_IP_ACCT) || defined(CONFIG_IP_FIREWALL)

static
int ipsm_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev=ptr;
	char *devname = dev->name;
	struct ip_fw *fw;
	int chn;

        WRITE_LOCK(&ip_fw_lock);

	if (event == NETDEV_UP) {
		for (chn = 0; chn < IP_FW_CHAINS; chn++)
			for (fw = *chains[chn]; fw; fw = fw->fw_next)
				if ((fw->fw_vianame)[0] && !strncmp(devname,
						fw->fw_vianame, IFNAMSIZ))
					fw->fw_viadev = dev;
	} else if (event == NETDEV_DOWN) {
		for (chn = 0; chn < IP_FW_CHAINS; chn++)
			for (fw = *chains[chn]; fw; fw = fw->fw_next)
				/* we could compare just the pointers ... */
				if ((fw->fw_vianame)[0] && !strncmp(devname,
						fw->fw_vianame, IFNAMSIZ))
					fw->fw_viadev = (struct net_device*)-1;
	}

        WRITE_UNLOCK(&ip_fw_lock);
	return NOTIFY_DONE;
}

static struct notifier_block ipsm_dev_notifier={
	ipsm_device_event,
	NULL,
	0
};

#endif

/*
 * "/proc" File handler to get command
 */
#define BUFFER_SIZE (1024 * 32) /* 32 KB estimates enough for this buffer size */
#if defined(BUF_SIZE)
#if (PAGE_SIZE < BUF_SIZE)
#undef  BUFFER_SIZE
#define BUFFER_SIZE PAGE_SIZE   /* for not enough page size system */
#endif
#endif

static char cmd_file[] = "net/ipsm_control";
static char *st_b = NULL; /* data buffer */

struct datas {
  int cmd;
  int length;
  char data[0];
};

/*
 * file_read_proc -- called when user reading
 */
static int file_read_proc(char *buf, char **start, off_t offset,
                   int count, int *eof, void *data)
{
    int return_length;

#ifdef DEBUG_IP_FIREWALL
    printk("**read_proc(), count = %d, off = %d\n",
           count, (int) offset);
#endif
    return_length = count > BUFFER_SIZE ? BUFFER_SIZE : count;

    memcpy(buf, st_b + offset, return_length);

    *start = buf + offset; /* update next start point */

    return return_length;
}

/*
 * file_read_proc -- called when user writing
 */
static int file_write_proc(struct file *file, const char *buf,
                     unsigned long count, void *data)
{
    int i, ret, cmd, length, datalen;
    struct datas *p;
#ifdef DEBUG_IP_FIREWALL
    printk("**write_proc(), count = %d\n", (int) count);
#endif
    length = count > BUFFER_SIZE ? BUFFER_SIZE : count; /* limit of max size */

    if (copy_from_user(st_b, buf, length)) {
      printk("ipsimple: cannot copy from user\n");
      return 0;
    }

    for(i = 0; i < length;) {
      p = (struct datas *) &st_b[i];
      cmd = p->cmd;
      datalen = p->length;
#ifdef DEBUG_IP_FIREWALL
      printk("write_file(), cmd = %d, point = %d, datalen = %d\n",
           cmd, i, datalen);
#endif
      ret = ipsm_ctl(cmd, p->data, datalen);
#ifdef DEBUG_IP_FIREWALL
      if (ret)
	printk("write_file(), ret = %d\n", ret);
#endif
      i += datalen + sizeof(struct datas);
    }
    return length;
}

static void file_create_proc(void)
{
    struct proc_dir_entry *entry;
    entry = create_proc_entry(cmd_file, 0, 0); /* "file" registration */
    entry->read_proc = file_read_proc; /* read routine */
    entry->write_proc = file_write_proc; /* write routine */
}

static void file_remove_proc(void)
{
    remove_proc_entry(cmd_file, NULL);
}

static void init_file_module(void)
{
    file_create_proc();
    st_b = (char *) vmalloc(BUFFER_SIZE);
    if (st_b == NULL) {
      printk("ipsimple: cannot vmalloc = %d\n", BUFFER_SIZE);
      file_remove_proc();
    }
    printk("ipsimple: init_file_module\n");
}

static void cleanup_file_module(void)
{
    if (st_b == NULL) {
      vfree(st_b);
    }
    file_remove_proc();
    printk("ipsimple: cleanup_file_module\n");
}

/*
 *
 */
int ipsm_init_or_cleanup(int init)
{
	int ret = 0;

	if (!init)
		goto cleanup;

	dprintf1("ipsm init\n");

	ret = ipsm_register_firewall(PF_INET, &ipsm_ops);
	if (ret < 0)
		goto cleanup_nothing;

	proc_net_create("ipsm_input", S_IFREG | S_IRUGO | S_IWUSR, ipsm_in_procinfo);

	init_file_module();

	/* Register for device up/down reports */
	register_netdevice_notifier(&ipsm_dev_notifier);

	return ret;

 cleanup:
	dprintf1("ipsm cleanup\n");

	unregister_netdevice_notifier(&ipsm_dev_notifier);

	cleanup_file_module();

	proc_net_remove("ipsm_input");
	free_fw_chain(chains[IP_FW_IN]);
	ipsm_unregister_firewall(PF_INET, &ipsm_ops);

 cleanup_nothing:
	return ret;
}
