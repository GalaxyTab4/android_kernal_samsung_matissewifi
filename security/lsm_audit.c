/*
 * common LSM auditing functions
 *
 * Based on code written for SELinux by :
 *			Stephen Smalley, <sds@epoch.ncsc.mil>
 * 			James Morris <jmorris@redhat.com>
 * Author : Etienne Basset, <etienne.basset@ensta.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
<<<<<<< HEAD
#include <linux/gfp.h>
=======
>>>>>>> 6e837fb... smack: implement logging V3
#include <linux/fs.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/audit.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/sctp.h>
#include <linux/lsm_audit.h>

/**
 * ipv4_skb_to_auditdata : fill auditdata from skb
 * @skb : the skb
 * @ad : the audit data to fill
 * @proto : the layer 4 protocol
 *
 * return  0 on success
 */
int ipv4_skb_to_auditdata(struct sk_buff *skb,
		struct common_audit_data *ad, u8 *proto)
{
	int ret = 0;
	struct iphdr *ih;

	ih = ip_hdr(skb);
	if (ih == NULL)
		return -EINVAL;

<<<<<<< HEAD
	ad->u.net->v4info.saddr = ih->saddr;
	ad->u.net->v4info.daddr = ih->daddr;
=======
	ad->u.net.v4info.saddr = ih->saddr;
	ad->u.net.v4info.daddr = ih->daddr;
>>>>>>> 6e837fb... smack: implement logging V3

	if (proto)
		*proto = ih->protocol;
	/* non initial fragment */
	if (ntohs(ih->frag_off) & IP_OFFSET)
		return 0;

	switch (ih->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *th = tcp_hdr(skb);
		if (th == NULL)
			break;

<<<<<<< HEAD
		ad->u.net->sport = th->source;
		ad->u.net->dport = th->dest;
=======
		ad->u.net.sport = th->source;
		ad->u.net.dport = th->dest;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *uh = udp_hdr(skb);
		if (uh == NULL)
			break;

<<<<<<< HEAD
		ad->u.net->sport = uh->source;
		ad->u.net->dport = uh->dest;
=======
		ad->u.net.sport = uh->source;
		ad->u.net.dport = uh->dest;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	case IPPROTO_DCCP: {
		struct dccp_hdr *dh = dccp_hdr(skb);
		if (dh == NULL)
			break;

<<<<<<< HEAD
		ad->u.net->sport = dh->dccph_sport;
		ad->u.net->dport = dh->dccph_dport;
=======
		ad->u.net.sport = dh->dccph_sport;
		ad->u.net.dport = dh->dccph_dport;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	case IPPROTO_SCTP: {
		struct sctphdr *sh = sctp_hdr(skb);
		if (sh == NULL)
			break;
<<<<<<< HEAD
		ad->u.net->sport = sh->source;
		ad->u.net->dport = sh->dest;
=======
		ad->u.net.sport = sh->source;
		ad->u.net.dport = sh->dest;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	default:
		ret = -EINVAL;
	}
	return ret;
}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
/**
 * ipv6_skb_to_auditdata : fill auditdata from skb
 * @skb : the skb
 * @ad : the audit data to fill
 * @proto : the layer 4 protocol
 *
 * return  0 on success
 */
int ipv6_skb_to_auditdata(struct sk_buff *skb,
		struct common_audit_data *ad, u8 *proto)
{
	int offset, ret = 0;
	struct ipv6hdr *ip6;
	u8 nexthdr;
<<<<<<< HEAD
	__be16 frag_off;
=======
>>>>>>> 6e837fb... smack: implement logging V3

	ip6 = ipv6_hdr(skb);
	if (ip6 == NULL)
		return -EINVAL;
<<<<<<< HEAD
	ad->u.net->v6info.saddr = ip6->saddr;
	ad->u.net->v6info.daddr = ip6->daddr;
=======
	ipv6_addr_copy(&ad->u.net.v6info.saddr, &ip6->saddr);
	ipv6_addr_copy(&ad->u.net.v6info.daddr, &ip6->daddr);
>>>>>>> 6e837fb... smack: implement logging V3
	ret = 0;
	/* IPv6 can have several extension header before the Transport header
	 * skip them */
	offset = skb_network_offset(skb);
	offset += sizeof(*ip6);
	nexthdr = ip6->nexthdr;
<<<<<<< HEAD
	offset = ipv6_skip_exthdr(skb, offset, &nexthdr, &frag_off);
=======
	offset = ipv6_skip_exthdr(skb, offset, &nexthdr);
>>>>>>> 6e837fb... smack: implement logging V3
	if (offset < 0)
		return 0;
	if (proto)
		*proto = nexthdr;
	switch (nexthdr) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph, *th;

		th = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
		if (th == NULL)
			break;

<<<<<<< HEAD
		ad->u.net->sport = th->source;
		ad->u.net->dport = th->dest;
=======
		ad->u.net.sport = th->source;
		ad->u.net.dport = th->dest;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr _udph, *uh;

		uh = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
		if (uh == NULL)
			break;

<<<<<<< HEAD
		ad->u.net->sport = uh->source;
		ad->u.net->dport = uh->dest;
=======
		ad->u.net.sport = uh->source;
		ad->u.net.dport = uh->dest;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	case IPPROTO_DCCP: {
		struct dccp_hdr _dccph, *dh;

		dh = skb_header_pointer(skb, offset, sizeof(_dccph), &_dccph);
		if (dh == NULL)
			break;

<<<<<<< HEAD
		ad->u.net->sport = dh->dccph_sport;
		ad->u.net->dport = dh->dccph_dport;
=======
		ad->u.net.sport = dh->dccph_sport;
		ad->u.net.dport = dh->dccph_dport;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	case IPPROTO_SCTP: {
		struct sctphdr _sctph, *sh;

		sh = skb_header_pointer(skb, offset, sizeof(_sctph), &_sctph);
		if (sh == NULL)
			break;
<<<<<<< HEAD
		ad->u.net->sport = sh->source;
		ad->u.net->dport = sh->dest;
=======
		ad->u.net.sport = sh->source;
		ad->u.net.dport = sh->dest;
>>>>>>> 6e837fb... smack: implement logging V3
		break;
	}
	default:
		ret = -EINVAL;
	}
	return ret;
}
#endif


static inline void print_ipv6_addr(struct audit_buffer *ab,
				   struct in6_addr *addr, __be16 port,
				   char *name1, char *name2)
{
	if (!ipv6_addr_any(addr))
<<<<<<< HEAD
		audit_log_format(ab, " %s=%pI6c", name1, addr);
=======
		audit_log_format(ab, " %s=%pI6", name1, addr);
>>>>>>> 6e837fb... smack: implement logging V3
	if (port)
		audit_log_format(ab, " %s=%d", name2, ntohs(port));
}

static inline void print_ipv4_addr(struct audit_buffer *ab, __be32 addr,
				   __be16 port, char *name1, char *name2)
{
	if (addr)
		audit_log_format(ab, " %s=%pI4", name1, &addr);
	if (port)
		audit_log_format(ab, " %s=%d", name2, ntohs(port));
}

/**
 * dump_common_audit_data - helper to dump common audit data
 * @a : common audit data
 *
 */
static void dump_common_audit_data(struct audit_buffer *ab,
				   struct common_audit_data *a)
{
<<<<<<< HEAD
=======
	struct inode *inode = NULL;
>>>>>>> 6e837fb... smack: implement logging V3
	struct task_struct *tsk = current;

	if (a->tsk)
		tsk = a->tsk;
	if (tsk && tsk->pid) {
		audit_log_format(ab, " pid=%d comm=", tsk->pid);
		audit_log_untrustedstring(ab, tsk->comm);
	}

	switch (a->type) {
<<<<<<< HEAD
	case LSM_AUDIT_DATA_NONE:
		return;
=======
>>>>>>> 6e837fb... smack: implement logging V3
	case LSM_AUDIT_DATA_IPC:
		audit_log_format(ab, " key=%d ", a->u.ipc_id);
		break;
	case LSM_AUDIT_DATA_CAP:
		audit_log_format(ab, " capability=%d ", a->u.cap);
		break;
<<<<<<< HEAD
	case LSM_AUDIT_DATA_PATH: {
		struct inode *inode;

		audit_log_d_path(ab, " path=", &a->u.path);

		inode = a->u.path.dentry->d_inode;
		if (inode) {
			audit_log_format(ab, " dev=");
			audit_log_untrustedstring(ab, inode->i_sb->s_id);
			audit_log_format(ab, " ino=%lu", inode->i_ino);
		}
		break;
	}
	case LSM_AUDIT_DATA_IOCTL_OP: {
		struct inode *inode;

		audit_log_d_path(ab, " path=", &a->u.op->path);

		inode = a->u.op->path.dentry->d_inode;
		if (inode) {
			audit_log_format(ab, " dev=");
			audit_log_untrustedstring(ab, inode->i_sb->s_id);
			audit_log_format(ab, " ino=%lu", inode->i_ino);
		}

		audit_log_format(ab, " ioctlcmd=%hx", a->u.op->cmd);
		break;
	}
	case LSM_AUDIT_DATA_DENTRY: {
		struct inode *inode;

		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, a->u.dentry->d_name.name);

		inode = a->u.dentry->d_inode;
		if (inode) {
			audit_log_format(ab, " dev=");
			audit_log_untrustedstring(ab, inode->i_sb->s_id);
			audit_log_format(ab, " ino=%lu", inode->i_ino);
		}
		break;
	}
	case LSM_AUDIT_DATA_INODE: {
		struct dentry *dentry;
		struct inode *inode;

		inode = a->u.inode;
		dentry = d_find_alias(inode);
		if (dentry) {
			audit_log_format(ab, " name=");
			audit_log_untrustedstring(ab,
					 dentry->d_name.name);
			dput(dentry);
		}
		audit_log_format(ab, " dev=");
		audit_log_untrustedstring(ab, inode->i_sb->s_id);
		audit_log_format(ab, " ino=%lu", inode->i_ino);
		break;
	}
=======
	case LSM_AUDIT_DATA_FS:
		if (a->u.fs.path.dentry) {
			struct dentry *dentry = a->u.fs.path.dentry;
			if (a->u.fs.path.mnt) {
				audit_log_d_path(ab, "path=", &a->u.fs.path);
			} else {
				audit_log_format(ab, " name=");
				audit_log_untrustedstring(ab,
						 dentry->d_name.name);
			}
			inode = dentry->d_inode;
		} else if (a->u.fs.inode) {
			struct dentry *dentry;
			inode = a->u.fs.inode;
			dentry = d_find_alias(inode);
			if (dentry) {
				audit_log_format(ab, " name=");
				audit_log_untrustedstring(ab,
						 dentry->d_name.name);
				dput(dentry);
			}
		}
		if (inode)
			audit_log_format(ab, " dev=%s ino=%lu",
					inode->i_sb->s_id,
					inode->i_ino);
		break;
>>>>>>> 6e837fb... smack: implement logging V3
	case LSM_AUDIT_DATA_TASK:
		tsk = a->u.tsk;
		if (tsk && tsk->pid) {
			audit_log_format(ab, " pid=%d comm=", tsk->pid);
			audit_log_untrustedstring(ab, tsk->comm);
		}
		break;
	case LSM_AUDIT_DATA_NET:
<<<<<<< HEAD
		if (a->u.net->sk) {
			struct sock *sk = a->u.net->sk;
=======
		if (a->u.net.sk) {
			struct sock *sk = a->u.net.sk;
>>>>>>> 6e837fb... smack: implement logging V3
			struct unix_sock *u;
			int len = 0;
			char *p = NULL;

			switch (sk->sk_family) {
			case AF_INET: {
				struct inet_sock *inet = inet_sk(sk);

<<<<<<< HEAD
				print_ipv4_addr(ab, inet->inet_rcv_saddr,
						inet->inet_sport,
						"laddr", "lport");
				print_ipv4_addr(ab, inet->inet_daddr,
						inet->inet_dport,
=======
				print_ipv4_addr(ab, inet->rcv_saddr,
						inet->sport,
						"laddr", "lport");
				print_ipv4_addr(ab, inet->daddr,
						inet->dport,
>>>>>>> 6e837fb... smack: implement logging V3
						"faddr", "fport");
				break;
			}
			case AF_INET6: {
				struct inet_sock *inet = inet_sk(sk);
				struct ipv6_pinfo *inet6 = inet6_sk(sk);

				print_ipv6_addr(ab, &inet6->rcv_saddr,
<<<<<<< HEAD
						inet->inet_sport,
						"laddr", "lport");
				print_ipv6_addr(ab, &inet6->daddr,
						inet->inet_dport,
=======
						inet->sport,
						"laddr", "lport");
				print_ipv6_addr(ab, &inet6->daddr,
						inet->dport,
>>>>>>> 6e837fb... smack: implement logging V3
						"faddr", "fport");
				break;
			}
			case AF_UNIX:
				u = unix_sk(sk);
<<<<<<< HEAD
				if (u->path.dentry) {
					audit_log_d_path(ab, " path=", &u->path);
=======
				if (u->dentry) {
					struct path path = {
						.dentry = u->dentry,
						.mnt = u->mnt
					};
					audit_log_d_path(ab, "path=", &path);
>>>>>>> 6e837fb... smack: implement logging V3
					break;
				}
				if (!u->addr)
					break;
				len = u->addr->len-sizeof(short);
				p = &u->addr->name->sun_path[0];
				audit_log_format(ab, " path=");
				if (*p)
					audit_log_untrustedstring(ab, p);
				else
					audit_log_n_hex(ab, p, len);
				break;
			}
		}

<<<<<<< HEAD
		switch (a->u.net->family) {
		case AF_INET:
			print_ipv4_addr(ab, a->u.net->v4info.saddr,
					a->u.net->sport,
					"saddr", "src");
			print_ipv4_addr(ab, a->u.net->v4info.daddr,
					a->u.net->dport,
					"daddr", "dest");
			break;
		case AF_INET6:
			print_ipv6_addr(ab, &a->u.net->v6info.saddr,
					a->u.net->sport,
					"saddr", "src");
			print_ipv6_addr(ab, &a->u.net->v6info.daddr,
					a->u.net->dport,
					"daddr", "dest");
			break;
		}
		if (a->u.net->netif > 0) {
			struct net_device *dev;

			/* NOTE: we always use init's namespace */
			dev = dev_get_by_index(&init_net, a->u.net->netif);
=======
		switch (a->u.net.family) {
		case AF_INET:
			print_ipv4_addr(ab, a->u.net.v4info.saddr,
					a->u.net.sport,
					"saddr", "src");
			print_ipv4_addr(ab, a->u.net.v4info.daddr,
					a->u.net.dport,
					"daddr", "dest");
			break;
		case AF_INET6:
			print_ipv6_addr(ab, &a->u.net.v6info.saddr,
					a->u.net.sport,
					"saddr", "src");
			print_ipv6_addr(ab, &a->u.net.v6info.daddr,
					a->u.net.dport,
					"daddr", "dest");
			break;
		}
		if (a->u.net.netif > 0) {
			struct net_device *dev;

			/* NOTE: we always use init's namespace */
			dev = dev_get_by_index(&init_net, a->u.net.netif);
>>>>>>> 6e837fb... smack: implement logging V3
			if (dev) {
				audit_log_format(ab, " netif=%s", dev->name);
				dev_put(dev);
			}
		}
		break;
#ifdef CONFIG_KEYS
	case LSM_AUDIT_DATA_KEY:
		audit_log_format(ab, " key_serial=%u", a->u.key_struct.key);
		if (a->u.key_struct.key_desc) {
			audit_log_format(ab, " key_desc=");
			audit_log_untrustedstring(ab, a->u.key_struct.key_desc);
		}
		break;
#endif
<<<<<<< HEAD
	case LSM_AUDIT_DATA_KMOD:
		audit_log_format(ab, " kmod=");
		audit_log_untrustedstring(ab, a->u.kmod_name);
		break;
=======
>>>>>>> 6e837fb... smack: implement logging V3
	} /* switch (a->type) */
}

/**
 * common_lsm_audit - generic LSM auditing function
 * @a:  auxiliary audit data
<<<<<<< HEAD
 * @pre_audit: lsm-specific pre-audit callback
 * @post_audit: lsm-specific post-audit callback
=======
>>>>>>> 6e837fb... smack: implement logging V3
 *
 * setup the audit buffer for common security information
 * uses callback to print LSM specific information
 */
<<<<<<< HEAD
void common_lsm_audit(struct common_audit_data *a,
	void (*pre_audit)(struct audit_buffer *, void *),
	void (*post_audit)(struct audit_buffer *, void *))
=======
void common_lsm_audit(struct common_audit_data *a)
>>>>>>> 6e837fb... smack: implement logging V3
{
	struct audit_buffer *ab;

	if (a == NULL)
		return;
	/* we use GFP_ATOMIC so we won't sleep */
	ab = audit_log_start(current->audit_context, GFP_ATOMIC, AUDIT_AVC);

	if (ab == NULL)
		return;

<<<<<<< HEAD
	if (pre_audit)
		pre_audit(ab, a);

	dump_common_audit_data(ab, a);

	if (post_audit)
		post_audit(ab, a);
=======
	if (a->lsm_pre_audit)
		a->lsm_pre_audit(ab, a);

	dump_common_audit_data(ab, a);

	if (a->lsm_post_audit)
		a->lsm_post_audit(ab, a);
>>>>>>> 6e837fb... smack: implement logging V3

	audit_log_end(ab);
}
