#ifndef _LINUX_VIRTIO_RXE_NET_H
#define _LINUX_VIRTIO_RXE_NET_H

#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>

/*feature bit map for vitio rxe driver */
//put these in later
#define VIRTIO_IB_F_STATUS 0 /*idk what this is yet*/

//This should be in virtio_ids.h
#define VIRTIO_ID_RXE 10

#define ETH_P_RXE (0x8915)

#endif
