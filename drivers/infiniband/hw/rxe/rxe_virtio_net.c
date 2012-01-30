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
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <rdma/ib_addr.h>
#include "rxe.h"
#include "rxe_virtio_net.h" 
//#define VIRT_IB_PROF
#ifdef VIRT_IB_PROF
#include <linux/timex.h>
#endif

#define MAX_FRAGS (65536/PAGE_SIZE + 2) 
#define MAX_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define SKB_SIZE (RXE_GRH_BYTES + MAX_PACKET_LEN + sizeof(struct sk_buff))

struct virtib_info {
   struct virtio_device *vdev;
   struct virtqueue *rvq; 
   struct virtqueue *svq;
   unsigned int status;
   unsigned int num;
   unsigned int max;
   struct scatterlist rx_sg[MAX_FRAGS + 2];
   struct scatterlist tx_sg[MAX_FRAGS + 2];
};

struct virtio_ib_config{
  __u8 mac_addr[6];
  __u16 status;
} __attribute__((packed));


static struct workqueue_struct *rxe_rcv_wq;
typedef struct{
   struct work_struct rxe_rcv_wk;
   struct virtqueue *rvq;
   struct virtib_info *vib;
}rxe_rcv_wk_t;

static struct workqueue_struct *refill_wq;
typedef struct{
   struct work_struct refill_wk;
   struct virtib_info *vib;
}refill_wk_t;

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
rxe_rcv_wk_t *rcv_work;
refill_wk_t *refill_work;
unsigned char mac_addr[6];
int mac_len;
int started = 0;
static struct work_struct add_rxe_wk;
static void ib_recv_done(struct virtqueue *rvq);
atomic_t rcv_lock = ATOMIC_INIT(1);
void ib_rcv_tasklet_fn(unsigned long data);
DEFINE_SPINLOCK(ib_rcv_lock);
DECLARE_TASKLET( ib_rcv_tasklet, ib_rcv_tasklet_fn, 8);

#ifdef VIRT_IB_PROF
cycles_t rcv_int_called;
cycles_t rcv_wk_called;
cycles_t rcv_wk_finished;
cycles_t start_get_buf;
cycles_t end_get_buf;
cycles_t start_rxe_rcv;
cycles_t end_rxe_rcv;
cycles_t start_queue_wk;
cycles_t end_queue_wk;
cycles_t start_vq_en;
cycles_t end_vq_en;
cycles_t start_vq_dis;
cycles_t end_vq_dis;
#endif

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
   mac_len = 6; 
   pr_warn("virtrxe_config_changed called\n");
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
   {
      return -ENOMEM;
      pr_warn("add_recvbuf: couldn't allocate skb\n");
   }
   skb_put(skb, RXE_GRH_BYTES + MAX_PACKET_LEN);
   num_sg = skb_to_sgvec(skb, vib->rx_sg, 0, skb->len);
   err = virtqueue_add_buf_gfp(vib->rvq, vib->rx_sg, 0 , num_sg, skb, gfp);
   if (err < 0)
   {
      kfree_skb(skb);
   }
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

static void rxe_refill_wk_func(struct work_struct *work)
{
   refill_wk_t *refill_wk = (refill_wk_t *)work;
   struct virtib_info *vib = refill_wk->vib;
      
   if(!try_fill_recv(vib, GFP_ATOMIC))
      pr_warn("rxe_rcv_wk_func: problem with refill\n"); 
}

static void rxe_rcv_wk_func(struct work_struct *work)
{
   rxe_rcv_wk_t *rxe_rcv_wk = (rxe_rcv_wk_t *)work;
   void * buf;
   unsigned int len;
   int iters = 0;
   struct sk_buff *skb;
   struct virtqueue *rvq = rxe_rcv_wk->rvq;
   struct rxe_pkt_info *pkt;
   struct virtib_info *vib = rxe_rcv_wk->vib; 
get_bufs:
   buf = virtqueue_get_buf(rvq, &len);  
   while (buf != NULL)
   { 
      --vib->num;
      skb = buf;
      skb->data_len = len;
/*
      pr_info("num frags is %d", skb_shinfo(skb)->nr_frags);
      pr_info("buf lenth recived is %d\n", len);
      pr_info("SKB_SIZE is %d\n", SKB_SIZE);
      pr_info("skb->tail is %d\n", skb->tail);
      pr_info("skb->head is %p\n", skb->head);
      pr_info("skb->head[0] is %x\n", skb->head[0]);
      pr_info("skb->len is %d\n", skb->len);
      int i;
      pr_info("ib_recv_done: printing the first 32 chars of data\n");
      for (i=0; i<= 30; i+=2)
      {
         pr_info("at %02x%02x\n", skb->data[i], skb->data[i+1]);
      }
*/
      pkt = SKB_TO_PKT(skb);
      pkt->rxe = grxe;
      pkt->port_num = 1;
      pkt->hdr = skb->data; 
      pkt->mask = RXE_GRH_MASK;
      rxe_rcv(skb);
      iters ++;
      buf = virtqueue_get_buf(rvq, &len);   
   }
   if(vib->num < 128)
   {
      queue_work(refill_wq, (struct work_struct *)refill_work);
   }
   
   if(!virtqueue_enable_cb(rvq))
   {
      iters = 0;
      virtqueue_disable_cb(rvq);
      goto get_bufs;
   }
   return;
}

void ib_rcv_tasklet_fn(unsigned long data)
{
   void * buf;
   unsigned int len;
   int iters = 0;
   struct sk_buff *skb;
   struct virtqueue *rvq = gvib->rvq; //rxe_rcv_wk->rvq;
   struct rxe_pkt_info *pkt;
   struct virtib_info *vib = gvib; //rxe_rcv_wk->vib; 
#ifdef VIRT_IB_PROF
   rcv_wk_called = get_cycles();
#endif
   atomic_inc(&rcv_lock);
get_bufs:
   buf = virtqueue_get_buf(rvq, &len);  
   while (buf != NULL)
   { 
      --vib->num;
      skb = buf;
      skb->data_len = len;
/*
      pr_info("num frags is %d", skb_shinfo(skb)->nr_frags);
      pr_info("buf lenth recived is %d\n", len);
      pr_info("SKB_SIZE is %d\n", SKB_SIZE);
      pr_info("skb->len is %d\n", skb->len);
      pr_info("skb->tail is %d\n", skb->tail);
      pr_info("skb->head is %p\n", skb->head);
      pr_info("skb->head[0] is %x\n", skb->head[0]);
      int i;
      pr_info("ib_recv_done: printing the first 32 chars of data\n");
      for (i=0; i<= 30; i+=2)
      {
         pr_info("at %02x%02x\n", skb->data[i], skb->data[i+1]);
      }
*/
      pkt = SKB_TO_PKT(skb);
      pkt->rxe = grxe;
      pkt->port_num = 1;
      pkt->hdr = skb->data; 
      pkt->mask = RXE_GRH_MASK;
      rxe_rcv(skb);
      iters ++;
      buf = virtqueue_get_buf(rvq, &len);   
   }
/*
   if(vib->num < 200 && !work_pending((struct work_struct *)refill_work))
   {
      queue_work(refill_wq, (struct work_struct *)refill_work);
   }
*/
   if(vib->num < 128)
   {
      if(!try_fill_recv(vib, GFP_ATOMIC))
         pr_warn("rxe_rcv_wk_func: problem with refill\n"); 
   }
   
   if(!virtqueue_enable_cb(rvq))
   {
      iters = 0;
      virtqueue_disable_cb(rvq);
      goto get_bufs;
   }
   atomic_dec(&rcv_lock);
#ifdef VIRT_IB_PROF
   rcv_wk_finished= get_cycles();
   pr_info("interrupt latency is %d time in tasklet %d total time %d",
           (rcv_wk_called - rcv_int_called)/3,
           (rcv_wk_finished - rcv_wk_called)/3,
           (rcv_wk_finished - rcv_int_called)/3);
#endif
   return;
}

static void ib_recv_done(struct virtqueue *rvq)
{
   //do recieve 
   //hard irq
   unsigned int flags;
   if(!atomic_dec_and_test(&rcv_lock))
   {
#ifdef VIRT_IB_PROF
      rcv_int_called= get_cycles();
#endif
      virtqueue_disable_cb(rvq);
      tasklet_hi_schedule(&ib_rcv_tasklet);
   }

/*
   unsigned int flags;
   if(rxe_rcv_wq)
   {
      if(rcv_work)
      {
         if(!work_pending((struct work_struct *)rcv_work))
         {
#ifdef VIRT_IB_PROF
            rcv_int_called= get_cycles();
#endif
            virtqueue_disable_cb(rvq);
            if(!queue_work(rxe_rcv_wq, (struct work_struct *)rcv_work))
            {
               pr_warn("failed to add to rcv work queue\n");
               BUG();
            }
         }
      }
   }
*/
}

static void ib_xmit_done(struct virtqueue *svq)
{
   pr_warn("ib_xmit_done called but not implemented\n");
}

static void release(struct rxe_dev *rxe)

{
   pr_warn("virt-ib release called\n");
   module_put(THIS_MODULE);
}
static __be64 rxe_mac_to_eui64 (void)
{
   __be64 eui64;
   unsigned char* dst = (unsigned char *)&eui64;
   pr_info("rxe: MAC is %02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2],
                           mac_addr[3], mac_addr[4], mac_addr[5]); 
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
      kfree_skb(skb);
   }
   return 0;
}

static int send(struct rxe_dev *rxe, struct sk_buff *skb)
{
   //pr_warn("send: called\n");
   int ret = 0;
   int num_sg = 0;
   struct virtib_info *vib = rxe->vinfo;
   //first free old skbs
   free_old_send_skbs(vib);
   //sg_set_buf(vib->tx_sg, skb, skb->truesize);
   num_sg = skb_to_sgvec(skb, vib->tx_sg, 0, skb->len);
/*
   int i = 0;
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
   ret = virtqueue_add_buf(vib->svq, vib->tx_sg, num_sg, 0, skb);
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
   return 0;
}

static int loopback (struct rxe_dev *rxe, struct sk_buff *skb)
{
   pr_warn("loopback called\n");
   return 0;
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
   struct ethhdr *eth;
   
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
   
   eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);
   eth->h_proto = skb->protocol;
   memcpy(eth->h_dest, av->ll_addr, ETH_ALEN);
   memcpy(eth->h_source, mac_addr, ETH_ALEN);
   if(addr_same(rxe, av))
   {
      pkt->mask |= RXE_LOOPBACK_MASK;
   }

   return skb;
}

static int init_av(struct rxe_dev *rxe, struct ib_ah_attr *attr, struct rxe_av *av)
{
   //pr_warn("init_av called\n");
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
   struct virtib_info *vib;
   struct virtqueue *vqs[2];
   vq_callback_t *callbacks[] = {ib_recv_done, NULL }; //ib_xmit_done
   const char *names[] = {"input", "output"};
   int err = 0; 
   struct rxe_dev *rxe;
   unsigned port_num;
   
   pr_warn("virtrxe_probe called\n");
   if(started)
   {
      pr_warn("virtrxe already running\n");
      return 1; 
   }
   started = 1;
   vib = kmalloc(sizeof(struct virtib_info), GFP_KERNEL);
   if(!vib)
   {
      pr_warn("Could not allocate virtual ib space\n"); 
      return 1;
   } 
   vib->num = 0;
   vib->max = 0;
   vib->status = 0;
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
   pr_info("vib->num is %d\n", vib->num);
   //create recieve workqueue
   rxe_rcv_wq = alloc_workqueue("rxe_rcv_queue", WQ_UNBOUND | WQ_HIGHPRI, 1);
   rcv_work = kmalloc(sizeof(rxe_rcv_wk_t), GFP_KERNEL);
   INIT_WORK((struct work_struct *)rcv_work, rxe_rcv_wk_func);
   rcv_work->rvq = vib->rvq;
   rcv_work->vib = vib;
   //create refill workqueue;
   refill_wq = alloc_workqueue("refill_queue", WQ_UNBOUND | WQ_HIGHPRI, 1);
   refill_work = kmalloc(sizeof(rxe_rcv_wk_t), GFP_KERNEL);
   INIT_WORK((struct work_struct *)refill_work, rxe_refill_wk_func);
   refill_work->vib = vib;

   //allocate rxe device memory
   pr_warn("allocating rxe memory\n");
   rxe = (struct rxe_dev *)ib_alloc_device(sizeof(*rxe));
   if (!rxe) {
      pr_warn("Could not allocate memory\n");
      return 1;
   }
   
   port_num = 1;
   rxe->ifc_ops = &ifc_ops;
   rxe->vinfo = vib;
   grxe = rxe;
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
   struct virtib_info *vib = vdev->priv;
   pr_warn("virtrxe_remove called\n");
   vdev->config->reset(vdev);
   free_unused_bufs(vib);
   vdev->config->del_vqs(vib->vdev);
   flush_workqueue(rxe_rcv_wq);
   destroy_workqueue(rxe_rcv_wq);
   flush_workqueue(refill_wq);
   destroy_workqueue(refill_wq);
   tasklet_kill( &ib_rcv_tasklet);
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
