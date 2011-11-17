#ifndef VHOST_RXE_H
#define VHOST_RXE_H

#include <net/sock.h>
#include <net/if_inet6.h>
#include <linux/vhost.h>

/*
 * this should be defined in .../include/linux/if_ether.h
 */
#define ETH_P_RXE			(0x8915)

/*
 * this should be defined in .../include/linux/netfilter.h
 * to a specific value
 */
#define NFPROTO_RXE			(0)

/*
 * these should be defined in .../include/linux/netfilter_rxe.h
 */
#define NF_RXE_IN			(0)
#define NF_RXE_OUT			(1)

/* Should probably move to something other than an array...these can be big */
#define RXE_MAX_IF_INDEX	(384)

struct vrxe_net_info{
   u8 using;
   u8 port;
   struct net_device *ndev;
   int status;
};

struct vrxe_mac_addr{
   __u8 mac_addr[6];
};

//define new ioctl for getting mac address
#define VHOST_GET_MAC _IOR(VHOST_VIRTIO, 0x31, struct vrxe_mac_addr)
extern struct vrxe_net_info vnet_info[RXE_MAX_IF_INDEX];
extern spinlock_t vnet_info_lock;
extern struct net_device *vib_ndev;

#endif
