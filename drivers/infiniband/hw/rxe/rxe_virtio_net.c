/* rxe_infiniband_driver using virtio
 *
 * By: Robert Lancaster
 *
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <rdma/ib_addr.h>
#include "rxe.h"
#include "rxe_virtio_net.h" 

#define MAX_FRAGS (65536/PAGE_SIZE + 2) 
#define MAX_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define SKB_SIZE (RXE_GRH_BYTES + MAX_PACKET_LEN + sizeof(struct sk_buff))

struct virtib_info {
   struct virtio_device *vdev;
   struct virtqueue *rvq; 
   struct virtqueue *svq;
   unsigned int status;
   int num;
   int max;
   struct scatterlist rx_sg[MAX_FRAGS + 2];
   struct scatterlist tx_sg[MAX_FRAGS + 2];
};

struct virtio_ib_config{
  __u8 mac_addr[6];
  __u16 status;
} __attribute__((packed));


static struct workqueue_struct *refill_rcv_wq;
typedef struct{
   struct work_struct refill_rcv_wk;
   struct virtqueue *rvq;
}refill_rcv_wk_t;

static struct workqueue_struct *rxe_rcv_wq;
typedef struct{
   struct work_struct rxe_rcv_wk;
   struct sk_buff *skb;
}rxe_rcv_wk_t;

static int rxe_eth_proto_id = ETH_P_RXE;
module_param_named(eth_proto_id, rxe_eth_proto_id, int, 0644);
MODULE_PARM_DESC(eth_proto_id, "Ethernet protocol ID (default/correct=0x8915)");

static int rxe_xmit_shortcut;
module_param_named(xmit_shortcut, rxe_xmit_shortcut, int, 0644);
MODULE_PARM_DESC(xmit_shortcut,
		 "Shortcut transmit (EXPERIMENTAL)");

static int rxe_loopback_mad_grh_fix = 1;
module_param_named(loopback_mad_grh_fix, rxe_loopback_mad_grh_fix, int, 0644);
MODULE_PARM_DESC(loopback_mad_grh_fix, "Allow MADs to self without GRH");

struct rxe_dev *grxe;
//setting up a global info struct - This a probably an awful idea
struct virtib_info *gvib;
unsigned char mac_addr[6];
int mac_len;
static struct work_struct add_rxe_wk;
static void ib_recv_done(struct virtqueue *rvq);

static void add_rxe_wk_func()
{
   int err;
   pr_warn("adding rxe\n");
   err = rxe_add(grxe, 1048);
   if (err)
   {
      pr_warn("Could not add rxe device\n");
   }
}

static void virtrxe_config_changed(struct virtio_device *vdev)
{
   pr_warn("virtrxe_config_changed called\n");
   mac_len = 6; 
   int err;
   //get mac address
   vdev->config->get(vdev,
                     offsetof(struct virtio_ib_config, mac_addr),
                     mac_addr, mac_len);
   pr_info("rxe: got mac of %x%x%x%x%x%x", mac_addr[0], mac_addr[1], mac_addr[2],
                           mac_addr[3], mac_addr[4], mac_addr[5]); 
   schedule_work(&add_rxe_wk);
}

static int add_recvbuf(struct virtib_info *vib, gfp_t gfp)
{
   struct sk_buff *skb;
   int err;
   int num_sg; 
   skb = alloc_skb(RXE_GRH_BYTES + MAX_PACKET_LEN, gfp);
   if(unlikely(!skb))
      return -ENOMEM;
   skb_put(skb, RXE_GRH_BYTES + MAX_PACKET_LEN);
   sg_set_buf(vib->rx_sg, skb, skb->truesize);
   num_sg = skb_to_sgvec(skb, vib->rx_sg+1, 0, skb->len);
   err = virtqueue_add_buf_gfp(vib->rvq, vib->rx_sg, 0 , num_sg+1, skb, gfp);
   if (err < 0)
      dev_kfree_skb(skb);
   return err;
}

static bool try_fill_recv(struct virtib_info *vib, gfp_t gfp)
{
   int err;
   int ret;
   do
   {
      err = add_recvbuf(vib, gfp);
      
      ret = err == -ENOMEM;
      if(err < 0)
         break;
      ++vib->num;
   } while(err > 0);
   if(unlikely(vib->num > vib->max))
      vib->max = vib->num;
   virtqueue_kick(vib->rvq);
   return !ret;
}

static void rxe_rcv_wk_func(struct work_struct *work)
{
   rxe_rcv_wk_t *rxe_rcv_wk = (rxe_rcv_wk_t *)work;
   struct sk_buff *skb = rxe_rcv_wk->skb;
   rxe_rcv(skb);
   return;
}

static void refill_rcv_wk_func(struct work_struct *work)
{
   refill_rcv_wk_t *refill_wk = (refill_rcv_wk_t *)work;
   struct virtib_info *vib = gvib;
   if(vib)
   {
      virtqueue_disable_cb(vib->rvq);
      try_fill_recv(vib, GFP_KERNEL);  
      if(!virtqueue_enable_cb(vib->rvq))
      {
         //new recives have arrived so process them
         pr_warn("refill_rcv_wk: new buffers added while refilling\n");
         //ib_recv_done(vib->rvq);
      }
      //pr_info("refill_rcv_wk: vib->max is %d gvib->num is %d", gvib->max, vib->num);
      return;
   }
   pr_warn("null vib given to work function\n");
}

static void ib_recv_done(struct virtqueue *rvq)
{
   //pr_info("ib_recv_done: called\n");
   void * buf;
   struct sk_buff *skb;
   struct rxe_pkt_info *pkt;
   refill_rcv_wk_t *work;
   rxe_rcv_wk_t *rcv_work;
   unsigned int len;
   unsigned char *test;
   int i;
   virtqueue_disable_cb(rvq);
   buf = virtqueue_get_buf(rvq, &len);
   if (!buf)
   {
      pr_info("null buffer returned by host\n");
   }
   else
   {
      gvib->num--;
      skb = buf;
      skb->head= buf + sizeof(struct sk_buff);
      skb->data = skb->head + skb->tail;
      skb->_skb_refdst = 0;
      skb->destructor = NULL;
      skb->sp = NULL;
      skb->nf_bridge = NULL;
      skb->nfct_reasm = NULL;
      //pr_info("num frags is %d", skb_shinfo(skb)->nr_frags);
/*
      pr_info("buf lenth recived is %d\n", len);
      pr_info("SKB_SIZE is %d\n", SKB_SIZE);
      pr_info("skb->tail is %d\n", skb->tail);
      pr_info("skb->head is %p\n", skb->head);
      pr_info("skb->head[0] is %x\n", skb->head[0]);
      pr_info("skb->len is %d\n", skb->len);
      pr_info("ib_recv_done: printing the first 32 chars of data\n");
      for (i=0; i<=skb->len; i+=2)
      {
         pr_info("at %02x%02x\n", skb->data[i], skb->data[i+1]);
      }
*/
      pkt = SKB_TO_PKT(skb);
      pkt->rxe = grxe;
      pkt->port_num = 1;
      pkt->hdr = skb->data; 
      pkt->mask = RXE_GRH_MASK;
      
      //do recieve
      if(rxe_rcv_wq)
      {
         rcv_work = kmalloc(sizeof(rxe_rcv_wk_t), GFP_ATOMIC);
         if(rcv_work)
         {
            INIT_WORK((struct work_struct *)rcv_work, rxe_rcv_wk_func);
            rcv_work->skb = skb;
            if(!queue_work(rxe_rcv_wq, (struct work_struct *)rcv_work))
            {
               pr_warn("failed to add to rcv work queue\n");
            }
         }
      }
      //refill queue on a workqueue;
      if(refill_rcv_wq)
      {
         work = kmalloc(sizeof(refill_rcv_wk_t), GFP_ATOMIC);
         if(work)
         {
            INIT_WORK((struct work_struct *)work, refill_rcv_wk_func);
            work->rvq = rvq;
            if(!queue_work(refill_rcv_wq, (struct work_struct *)work))
            {
               pr_warn("failed to add work queue\n");
            }
         }
      }
      if(!virtqueue_enable_cb(rvq))
      {
         //new recives have arrived so process them
         pr_warn("ib_recv_done: new buffers added while processing current\n");
         //ib_recv_done(vib->rvq);
      }
   }
   
}

static void ib_xmit_done(struct virtqueue *svq)
{
   pr_warn("ib_xmit_done called by not implemented\n");
}

static void release(struct rxe_dev *rxe)
{
   module_put(THIS_MODULE);
}
static __be64 rxe_mac_to_eui64 (void)
{
   pr_info("rxe: MAC is %02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2],
                           mac_addr[3], mac_addr[4], mac_addr[5]); 
   __be64 eui64;
   unsigned char* dst = (unsigned char *)&eui64;
   dst[0] = mac_addr[0] ^ 2;
   dst[1] = mac_addr[1];
   dst[2] = mac_addr[2];
   dst[3] = 0xff;
   dst[4] = 0xfe;
   dst[5] = mac_addr[3];
   dst[6] = mac_addr[4];
   dst[7] = mac_addr[5];
   return eui64;
}
static __be64 node_guid(struct rxe_dev *rxe)
{
   //set a static guid for now
   return rxe_mac_to_eui64();
}

static __be64 port_guid(struct rxe_dev *rxe, unsigned int port_num)
{
   //again a static guid for now
   return rxe_mac_to_eui64();
}

static struct device *dma_device(struct rxe_dev *rxe)
{
   //I don't think this pretains to us
   pr_warn("dma_device called\n");
   return NULL;
}

static int mcast_add(struct rxe_dev *rxe, union ib_gid *mgid)
{
   //support later probably have to add an ioctl
   return 1;
}

static int mcast_delete(struct rxe_dev *rxe, union ib_gid *mgid)
{
   //support later probably have to add an ioctl
   return 1;
}

static inline int queue_deactivated(struct sk_buff *skb)
{
   pr_warn("queue_deactivated called\n");
   return 0;
}

static unsigned int free_old_send_skbs(struct virtib_info *vib)
{
   struct sk_buff *skb;
   unsigned int len;
   while((skb = virtqueue_get_buf(vib->svq, &len)) != NULL)
   {
      skb->head += PAGE_OFFSET;
      kfree_skb(skb);
   }
}

static int send(struct rxe_dev *rxe, struct sk_buff *skb)
{
   //pr_warn("send: called\n");
   int ret = 0;
   int i = 0;
   struct virtib_info *vib = rxe->vinfo;
   //first free old skbs
   free_old_send_skbs(vib);
   sg_set_buf(vib->tx_sg, skb, skb->truesize);
   int num_sg = skb_to_sgvec(skb, vib->tx_sg+1, 0, skb->len);
/*
   pr_warn("send: skb->len is %d\n", skb->len);
   pr_info("num frags is %d\n", skb_shinfo(skb)->nr_frags);
   pr_info("fclone is %x\n", skb->fclone);
   pr_info("skb data addr is %p\n", skb->data);
   pr_info("printing the first 32 chars of data\n");
   for (i=0; i<36; i++)
   {
      pr_info("at %p: %04x,",&skb->data[i], skb->data[i]);
   }
   pr_warn("skb addr is: %p\n", skb);
*/
   ret = virtqueue_add_buf(vib->svq, vib->tx_sg, num_sg + 1, 0, skb);
   //kick the virtqueue
   skb_orphan(skb);
   nf_reset(skb);
   virtqueue_kick(vib->svq);
   //pr_warn("send: return is %u\n", ret);
   return ret;
}

static int loopback_finish(struct sk_buff *skb)
{
   pr_warn("loopback_finish called\n");
}

static int loopback (struct rxe_dev *rxe, struct sk_buff *skb)
{
   pr_warn("loopback called\n");
}

void dump_skb(struct sk_buff *skb)
{
   pr_info("skb: %p, head = %p, data = %p, tail = %d, end = %d, len = %d, data_len = %d\n", skb, skb->head, skb->data, skb->tail, skb->end, skb->len, skb->data_len);
   pr_info("       truesize = %d, mac_len = %d, hdr_len = %d, transport_header = %d, network_header = %d, mac_header = %d\n",
   skb->truesize, skb->mac_len, skb->hdr_len, skb->transport_header, skb->network_header, skb->mac_header);
}

static inline int addr_same(struct rxe_dev *rxe, struct rxe_av *av)
{
   int port_num = 1;
   return rxe->port[port_num - 1].guid_tbl[0]
      == av->attr.grh.dgid.global.interface_id;
}

static struct sk_buff *init_packet(struct rxe_dev *rxe, struct rxe_av *av, int paylen, int align)
{
   //pr_warn("init_packet called\n");
   struct sk_buff *skb;
   struct rxe_pkt_info *pkt;
   
   //need to know how much space to reserve using MAX len for now
   skb = alloc_skb(paylen + RXE_GRH_BYTES + MAX_PACKET_LEN, GFP_ATOMIC);
   if(!skb)
   {
      pr_warn("failed to allocate skb\n");
   } 
   skb_reserve(skb, MAX_PACKET_LEN);
   skb_reset_network_header(skb);
   
   skb->protocol = htons(rxe_eth_proto_id);
   pkt = SKB_TO_PKT(skb);
   pkt->rxe = rxe;
   pkt->port_num = 1;
   pkt->hdr = skb_put(skb, RXE_GRH_BYTES + paylen);
   pkt->mask = RXE_GRH_MASK;

   //should set device and hard_header on host side?
   if(addr_same(rxe, av))
   {
      pkt->mask |= RXE_LOOPBACK_MASK;
   }

   return skb;
}

static int init_av(struct rxe_dev *rxe, struct ib_ah_attr *attr, struct rxe_av *av)
{
   pr_warn("init_av called\n");
   struct in6_addr *in6 = (struct in6_addr *)attr->grh.dgid.raw;

   /* grh required for rxe_net */
   if ((attr->ah_flags & IB_AH_GRH) == 0) {
	if (rxe_loopback_mad_grh_fix) {
		/* temporary fix so that we can handle mad's to self
		   without grh's included add grh pointing to self */
		attr->ah_flags |= IB_AH_GRH;
		attr->grh.dgid.global.subnet_prefix
			= rxe->port[0].subnet_prefix;
		attr->grh.dgid.global.interface_id
			= rxe->port[0].guid_tbl[0];
		av->attr = *attr;
	} else {
		pr_info("rxe_net: attempting to init av without grh\n");
		return -EINVAL;
	}
   }

   if (rdma_link_local_addr(in6))
	rdma_get_ll_mac(in6, av->ll_addr);
   else if (rdma_is_multicast_addr(in6))
	rdma_get_mcast_mac(in6, av->ll_addr);
   else {
	int i;
	char addr[64];

	for (i = 0; i < 16; i++)
		sprintf(addr+2*i, "%02x", attr->grh.dgid.raw[i]);

	pr_info("rxe_net: non local subnet address not supported %s\n",
		addr);
	return -EINVAL;
   }

return 0;
 
}

static char *parent_name(struct rxe_dev *rxe, unsigned int port_num)
{
   pr_warn("parent_name called\n");
   return "rxe_virtio";
}

static enum rdma_link_layer link_layer(struct rxe_dev *rxe, unsigned int port_num)
{
   return IB_LINK_LAYER_ETHERNET;
}

static struct rxe_ifc_ops ifc_ops = {
   .release       = release,
   .node_guid     = node_guid,
   .port_guid     = port_guid,
   .dma_device    = dma_device,
   .mcast_add     = mcast_add,
   .mcast_delete  = mcast_delete,
   .send          = send,
   .loopback      = loopback,
   .init_packet   = init_packet,
   .init_av       = init_av,
   .parent_name   = parent_name,
   .link_layer    = link_layer,
};

static int virtrxe_probe(struct virtio_device *vdev)
{
   //call rxe_setup code here
   pr_warn("virtrxe_probe called\n");
   struct virtib_info *vib;
   struct virtqueue *vqs[2];
   vq_callback_t *callbacks[] = {ib_recv_done, NULL }; //ib_xmit_done
   const char *names[] = {"input", "output"};
   int err = 0; 
   vib = kmalloc(sizeof(struct virtib_info), GFP_KERNEL);
   if(!vib)
   {
      pr_warn("Could not allocate virtual ib space\n"); 
      return 1;
   } 
   vib->vdev = vdev;
   gvib = vib;
   vdev->priv = vib; 
   err = vdev->config->find_vqs(vdev, 2, vqs, callbacks, names);
   if(err)
   {
      pr_warn("find vqs failed\n");
   }
	
   vib->rvq = vqs[0];
   vib->svq = vqs[1];

   //need to fill rvq
   try_fill_recv(vib, GFP_KERNEL);
   if(vib->num == 0)
   {
      pr_warn("rxe: failed to fill receive buffer\n");
   }
   //create refill workqueue
   refill_rcv_wq = create_workqueue("refill_rcv_queue");
   //create recieve workqueue
   rxe_rcv_wq = create_workqueue("rxe_rcv_queue");
   //add an rxe device
   struct rxe_dev *rxe;
   unsigned port_num;
   //allocate device memory
   pr_warn("allocating rxe memory\n");
   rxe = (struct rxe_dev *)ib_alloc_device(sizeof(*rxe));
   if (!rxe) {
      pr_warn("Could not allocate memory\n");
      return 1;
   }
   
   port_num = 1;
   rxe->ifc_ops = &ifc_ops;
   rxe->vinfo = vib;

/* 
   pr_warn("adding rxe\n");
   err = rxe_add(rxe, 1048);
   if (err)
   {
      pr_warn("Could not add rxe device\n");
   }
*/
   grxe = rxe;
   //attempt to fill recv buff here
   pr_warn("done with rxe init\n");
   return 0;
}
static void free_unused_bufs(struct virtib_info *vib)
{
   void *buf;
   while(1)
   {
      buf = virtqueue_detach_unused_buf(vib->svq);
      if (!buf)
         break;
      dev_kfree_skb(buf);
   }
   while(1)
   {
      buf = virtqueue_detach_unused_buf(vib->rvq);
      if(!buf)
         break;
      dev_kfree_skb(buf);
      --vib->num;
   }
   BUG_ON(vib->num != 0);
}
static void __devexit virtrxe_remove(struct virtio_device *vdev)
{
   pr_warn("virtrxe_remove called\n");
   struct virtib_info *vib = vdev->priv;
   vdev->config->reset(vdev);
   free_unused_bufs(vib);
   vdev->config->del_vqs(vib->vdev);
   flush_workqueue(refill_rcv_wq);
   destroy_workqueue(refill_rcv_wq);
   flush_workqueue(rxe_rcv_wq);
   destroy_workqueue(rxe_rcv_wq);
   if(grxe)
      rxe_remove(grxe);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RXE, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

//fill these in as we go
static unsigned int features[] = {
   VIRTIO_IB_F_STATUS,
};

static struct virtio_driver virtio_rxe_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtrxe_probe,  
	.remove =	__devexit_p(virtrxe_remove),  
	.config_changed = virtrxe_config_changed, 
};

static int __init init(void)
{
        INIT_WORK(&add_rxe_wk, add_rxe_wk_func);
	pr_warn("rxe guest driver loaded\n");
	return register_virtio_driver(&virtio_rxe_driver);
}

static void __exit fini(void)
{
	pr_warn("rxe guest driver removed\n");
	unregister_virtio_driver(&virtio_rxe_driver);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio rxe driver");
MODULE_VERSION("0.0.1");
MODULE_AUTHOR("Robert Lancaster");
MODULE_LICENSE("GPL");
