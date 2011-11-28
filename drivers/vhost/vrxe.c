/*
 * virtio-rxe server in host kernel
 *
 * By: Robert Lancaster
 *
 * For now will be located in the /infiniband/hw/rxe folder
 *
 * This driver is simply a recive and send interface with the associated network device
 * it passes the appropriate IBoE messages up to the correct guest.
 */

#include <linux/vhost.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/virtio_net.h>
#include <rdma/ib_verbs.h>

#include "vrxe.h"
#include "vhost.h"

enum {
   VHOST_IB_VQ_RX = 0,
   VHOST_IB_VQ_TX = 1,
   VHOST_IB_VQ_MAX = 2,
};

struct vhost_ib {
   struct vhost_dev dev;
   struct vhost_virtqueue vqs[VHOST_IB_VQ_MAX];
   //struct net_device *ndev;
};

//define send workqueue struct
static struct workqueue_struct *rcv_wq;

typedef struct {
   struct work_struct rcv_wk;
   struct sk_buff *skb;
} rcv_wk_t;

static int rxe_eth_proto_id = ETH_P_RXE;
struct vrxe_net_info vnet_info[RXE_MAX_IF_INDEX];
spinlock_t vnet_info_lock;
struct net_device *vib_ndev;
struct vhost_virtqueue *rvq;
struct vhost_dev *gdev;


static int send_finish(struct sk_buff *skb)
{
   //pr_warn("send finish called\n");
   return skb->dev->netdev_ops->ndo_start_xmit(skb, skb->dev);
}
static void handle_tx(struct vhost_ib *ib)
{
   //pr_warn("handle_tx called\n");
   struct vhost_virtqueue *vq = &ib->dev.vqs[VHOST_IB_VQ_TX];
   unsigned out; 
   unsigned in; 
   unsigned s;
   struct vring_desc *skb_desc;
   struct vring_desc *data_desc;
   struct scatterlist *sg;
   struct sk_buff *skb;
   struct skb_shared_info *shinfo;
   int len;
   int head;
   int i;
   u8 ll_addr[16] = {0, 0x90, 0x47, 0x03, 0x8a, 0x35, 0, 0, 0, 0, 0, 0, 0, 0,0,0};
   
   mutex_lock(&vq->mutex);
   vhost_disable_notify(vq);

   for (;;)
   {
      head = vhost_get_vq_desc(&ib->dev, vq, vq->iov, 
                ARRAY_SIZE(vq->iov),
                &out, &in,
                NULL, NULL);
      if(head < 0)
      {
         pr_warn("handle_tx: error getting buffer from host tx queue\n");
         break;
      }
      if (head == vq->num)
      {
         //nothing new?
         //pr_info("vhost_ib: head is %d vq num is %d\n", head, vq->num);
         //reenable notification
         if(unlikely(vhost_enable_notify(vq)))
         {
            vhost_disable_notify(vq);
            continue;
         }
         break;
      }
      if (in)
      {
         vq_err(vq, "Unexpected descriptor format for TX: out %d, in %d\n", out, in);
         break;
      }
      len = iov_length(vq->iov, out);
      skb_desc = (struct vring_desc*)&vq->iov[0].iov_base;
      data_desc = (struct vring_desc*)&vq->iov[1].iov_base;
      //set skb pointer 
      skb = skb_desc->addr;
      skb->data = data_desc->addr; 
      skb->head = skb->head - PAGE_OFFSET; 
      skb->dev = vib_ndev;
      //add a new user to this skb
      atomic_inc(&skb->users);
/*
      pr_info("handle_tx: skb iov length is %d\n", len);
      pr_info("handle_tx: skb len is %d\n", skb->len);
      pr_info("data before setting header\n");
      for (i=0; i<36; i++)
      {
         pr_info("at %p:  %04x,", &skb->data[i], skb->data[i]);
      }
*/
      dev_hard_header( skb, skb->dev, 
                        rxe_eth_proto_id,
                        ll_addr,
                        skb->dev->dev_addr, 
                        skb->len );
/*
      pr_info("data after setting header\n");
      for (i=0; i<36; i++)
      {
         pr_info(" %04x,", skb->data[i]);
      }
*/
      NF_HOOK(NFPROTO_RXE, NF_RXE_OUT, 
                skb, skb->dev, NULL, send_finish);
      vhost_add_used(vq, head, len);  
   }
   mutex_unlock(&vq->mutex);
}

static void rcv_wk_func( struct work_struct *work)
{
   int head;
   int in;
   int out;
   int len;
   int i;
   rcv_wk_t *rcv_wk = (rcv_wk_t *)work;
//   pr_info("rcv_wk_func called\n");
//   pr_info("The size of recived sk_buff is %d\n", rcv_wk->skb->truesize);
//   pr_info("The size of recived sk_buff data is %d\n", rcv_wk->skb->len);
   if(!vhost_vq_access_ok(rvq))
   {
      pr_warn("failed to access vq\n");
      goto err;
   }   
   mutex_lock(&rvq->mutex);
   vhost_disable_notify(rvq);
   for(;;)
   {
      head = vhost_get_vq_desc(rvq->dev, rvq, rvq->iov,
            ARRAY_SIZE(rvq->iov),
            &out, &in,
            NULL, NULL);
      //if we are equal to vq size this is a problem
      if(head == rvq->num)
      {
         if(unlikely(vhost_enable_notify(rvq)))
         {
           pr_warn("cannot renable notify\n");
           vhost_disable_notify(rvq);
           continue;
         }
         pr_warn("head is equal to max vq length. need to handle this\n");
         goto err;
      }
      //if we get an output buffer or no input buffer this is bad
      if(unlikely(out || in <= 0)) 
      {
         pr_warn("unexpected descirptior format for RX: out: %d, in: %d head: %d\n",
            out, in, head);
         goto err;
      }
      if(unlikely(head < 0))
      {
         pr_warn("head is less than 0: %d", head);
         goto err;
      }
      //pr_info("vhost_rcv_wk: success! head is: %d vq num is: %d in: %d\n", 
      //             head, rvq->num, in);
      //Copy data into iovec this seems like the only way to do this
      len = iov_length(rvq->iov, in);
      skb_reset_tail_pointer(rcv_wk->skb);
/*
      for (i=0; i<rcv_wk->skb->len; i+=2)
      {
         pr_info(" %02x%02x,", rcv_wk->skb->data[i], rcv_wk->skb->data[i+1]);
      }
*/
      if(memcpy_toiovecend(rvq->iov, rcv_wk->skb, 0, sizeof(struct sk_buff)) < 0)
      {
         pr_warn("failed to copy skb to iovec\n");
         goto err;
      }
      if(memcpy_toiovecend(rvq->iov, rcv_wk->skb->head, sizeof(struct sk_buff) ,
          rcv_wk->skb->len + rcv_wk->skb->tail) < 0)
      {
         pr_warn("failed to copy skb->data to iovec\n");
         goto err;
      }
      //pr_info("adding used with length: %d\n", len);
      vhost_add_used_and_signal(rvq->dev, rvq, head, len);  
      vhost_enable_notify(rvq); 
      goto finish;
   }
 
err:
   vhost_discard_vq_desc(rvq,1);
   pr_info("freeing skb\n");
   kfree_skb(rcv_wk->skb);

finish:
   mutex_unlock(&rvq->mutex);

   return;
}

int handle_rx(struct sk_buff *skb)
{
   int ret;
   //basically I have to move all of this to a workqueue since it takes too long
   //and requires context switching (due to mutex) to get the data up to the guest
   rcv_wk_t *work;
   if(rcv_wq)
   {
      work = kmalloc(sizeof(rcv_wk_t), GFP_ATOMIC);
      if(work)
      {
         INIT_WORK((struct work_struct *)work, rcv_wk_func);
         work->skb = skb;
         ret = queue_work(rcv_wq, (struct work_struct *)work);
      }
   }
   return 0;
}

static void handle_tx_kick(struct vhost_work *work)
{
   //pr_warn("handle_tx_kick called\n");
   struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue, poll.work);
   struct vhost_ib *ib = container_of(vq->dev, struct vhost_ib, dev);
  
   //check to see if this works
   //pr_warn("ib->dev.nvqs is: %d\n", ib->dev.nvqs);
   //pr_warn("vq address is %p\n", &vq);
   //pr_warn("tx address is %p rx address is %p\n", &ib->dev.vqs[1], &ib->dev.vqs[0]);
   //pr_warn("tx address is %p rx address is %p\n", &ib->vqs[1], &ib->vqs[0]);
   //pr_warn("avail tx address is %p\n", ib->dev.vqs[1].avail);
   //pr_warn("avail num_free is %d at %p\n", ib->dev.vqs[1].avail_idx, &ib->dev.vqs[1].avail_idx);

   handle_tx(ib);
}

static void handle_rx_kick(struct vhost_work *work)
{
   //pr_warn("handle_rx_kick called\n");
   //struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue, poll.work);
   //struct vhost_ib *ib = container_of(vq->dev, struct vhost_ib, dev);
   //handle_rx(ib);
}

/* Copy argument and remove trailing CR. Return the new length. */
static int sanitize_arg(const char *val, char *intf, int intf_len)
{
   int len;
   
   if (!val)
      return 0;
   
   /* Remove newline. */
   for (len = 0; len < intf_len - 1 && val[len] && val[len] != '\n'; len++)
      intf[len] = val[len];
   intf[len] = 0;
   
   if (len == 0 || (val[len] != 0 && val[len] != '\n'))
      return 0;
   
   return len;
}

static int can_support_rxe(struct net_device *ndev)
{
   int rc = 0;
   
   if (ndev->ifindex >= RXE_MAX_IF_INDEX) {
   	pr_debug("%s index %d: too large for rxe ndev table\n",
   		 ndev->name, ndev->ifindex);
   	goto out;
   }
   
   /* Let's says we support all ethX devices */
   if (strncmp(ndev->name, "eth", 3) == 0)
   	rc = 1;
   
out:
   return rc;
}

static int vhost_rxe_open(struct inode *inode, struct file *f)
{
   pr_warn("vhost_rxe_open called\n");
   struct vhost_ib *n = kmalloc(sizeof *n, GFP_KERNEL);
   struct vhost_dev *dev;
   int r;

   dev = &n->dev;
   n->vqs[VHOST_IB_VQ_TX].handle_kick = handle_tx_kick;
   n->vqs[VHOST_IB_VQ_RX].handle_kick = handle_rx_kick;
   r = vhost_dev_init(dev, n->vqs, VHOST_IB_VQ_MAX);
   if (r < 0){
      kfree(n);
      return r;
   }
   pr_warn("rxe_open: tx avail: %p rx avail: %p\n", 
      &n->vqs[VHOST_IB_VQ_TX].avail,
      &n->vqs[VHOST_IB_VQ_RX].avail);
   
   pr_warn("rxe_open: tx addr: %p rx addr: %p\n", 
      &n->vqs[VHOST_IB_VQ_TX],
      &n->vqs[VHOST_IB_VQ_RX]);

   f->private_data = n;
   return 0;
}

static long vhost_rxe_compat_ioctl(struct file *f, unsigned int ioctl,
                                    unsigned long arg)
{
   pr_warn("vhost_rxe_compat_ioctl called\n");
   return 0;
}

static int set_backend(struct vhost_ib *n, char* val)
{
   int i = 0;
   char intf[32];
   struct vhost_virtqueue *vq;
   mutex_lock(&n->dev.mutex);
   int ret;

   ret = vhost_dev_check_owner(&n->dev);
   if(ret)
   {
      pr_warn("vhost_ib: dev_check_owner failed\n");
   }
   
   vq = n->vqs + 1;
   mutex_lock(&vq->mutex);
   //check vq access
   if(!vhost_vq_access_ok(vq))
   {
      pr_warn("vhost_ib: vq access check failed\n");
   }
   rvq = &n->vqs[VHOST_IB_VQ_RX];
   gdev = &n->dev;
   //test lock unlock
   mutex_lock(&rvq->mutex);
   mutex_unlock(&rvq->mutex);
   pr_warn("got rvq mutex lock\n");
   mutex_unlock(&vq->mutex);
   mutex_unlock(&n->dev.mutex);

   int len = sanitize_arg(val, intf, sizeof(intf));
   if (!len)
   {
      pr_err("Invalid interface passed to vhost_ib\n");
      return -EINVAL;
   }
   
   spin_lock_bh(&vnet_info_lock);
   for(i = 0; i < RXE_MAX_IF_INDEX; i++)
   {
      struct net_device *ndev = vnet_info[i].ndev;
      if (ndev && (0 == strncmp(intf, ndev->name, len)))
      {
         spin_unlock_bh(&vnet_info_lock);
         if(vnet_info[i].using)
         {
            pr_info("vhost_ib: already configured on %s\n", intf);
         }
         else
         {
            pr_info("vhost_ib: configured on %s\n", intf);
            vib_ndev = ndev;
            vnet_info[i].using = 1;
            //set port state?
         }
         return 0;
      }
   }
   spin_unlock_bh(&vnet_info_lock);
   pr_warning("interface %s not found\n", intf);
   return 0;
}

static long vhost_rxe_ioctl(struct file *f, unsigned int ioctl,
                                    unsigned long arg)
{
   struct vhost_ib *n = f->private_data;
   int r = 0;
   void __user *argp = (void __user *)arg;
   u64 __user *featurep = argp;
   u64 features;
   __u8 __user *mac_addrp = argp;
   char intf[32];
   //pr_warn("vhost_rxe_ioctl called: %X\n", ioctl);
   switch(ioctl)
   {
      case VHOST_NET_SET_BACKEND:
         pr_warn("VHOST_NET_SET_BACKEND called\n");
         if(copy_from_user(intf, argp, sizeof intf))
         {
            return -EFAULT;
         }
         pr_warn("dev name is %s\n", intf);
         r = set_backend(n, intf);
         return 0;
      case VHOST_GET_FEATURES:
         pr_warn("VHOST_GET_FEATURES\n");
	 pr_warn("vhost sending features of %08x\n", features);
         features = VHOST_FEATURES;
         if (copy_to_user(featurep, &features, sizeof features))
            return -EFAULT;
         return 0;
      case VHOST_SET_FEATURES:
         pr_warn("VHOST_SET_FEATURES called \n");
         if(copy_from_user(&features, featurep, sizeof features))
         {
            return -EFAULT;
         }
	 pr_warn("vhost features is %08x\n", features);
         if(features & ~VHOST_FEATURES)
         {
	    return -EFAULT;
         }
         return 0;
      case VHOST_RESET_OWNER:
         pr_warn("VHOST_RESET_OWNER called but not implemented\n");
         return 0;
      case VHOST_GET_MAC:
         pr_warn("VHOST_GET_MAC called\n");
         if (!vib_ndev)
         {
            pr_warn("vib_ndev is null : %p", vib_ndev);
            return -EFAULT;
         }
         if(copy_to_user(mac_addrp, vib_ndev->dev_addr, vib_ndev->addr_len))
         {
            return -EFAULT;
         } 
         return 0;
      default:
         mutex_lock(&n->dev.mutex);
         r=vhost_dev_ioctl(&n->dev, ioctl, arg);
         mutex_unlock(&n->dev.mutex);
         return r;
   }
}

static int vhost_rxe_release(struct inode *inode, struct file *f)
{
   struct vhost_ib *n = f->private_data;
   pr_warn("vhost_rxe_release called\n");
   //for now just free structures
   kfree(n);
   return 0;
}

static const struct file_operations vhost_rxe_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_rxe_release,//add this
	.unlocked_ioctl = vhost_rxe_ioctl,//add this
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_rxe_compat_ioctl,//add this
#endif
	.open           = vhost_rxe_open,   //add this
	.llseek		= noop_llseek,
};

static int rxe_notify(struct notifier_block *not_blk,
		      unsigned long event,
		      void *arg)
{
   struct net_device *ndev = arg;
   
   if (!can_support_rxe(ndev))
   	goto out;
   
   spin_lock_bh(&vnet_info_lock);
   switch (event) {
   case NETDEV_REGISTER:
      /* Keep a record of this NIC. */
      vnet_info[ndev->ifindex].status = IB_PORT_DOWN;
      vnet_info[ndev->ifindex].using = 0;
      vnet_info[ndev->ifindex].port = 1;
      vnet_info[ndev->ifindex].ndev = ndev;
      break;
   
   case NETDEV_UNREGISTER:
      if (vnet_info[ndev->ifindex].using) {
         vnet_info[ndev->ifindex].using = 0;
         spin_unlock_bh(&vnet_info_lock);
         //find some way to tell guest the network is down
         //rxe_remove(rxe);
         spin_lock_bh(&vnet_info_lock);
      }
      vnet_info[ndev->ifindex].status = 0;
      vnet_info[ndev->ifindex].port = 0;
      vnet_info[ndev->ifindex].ndev = NULL;
      break;
   
   case NETDEV_UP:
      //rxe_net_up(ndev);
      break;
   
   case NETDEV_DOWN:
      //rxe_net_down(ndev);
      break;
   
   case NETDEV_CHANGEMTU:
      //rxe = net_to_rxe(ndev);
      //if (rxe) {
      //	pr_info("rxe_net: %s changed mtu to %d\n",
      //		ndev->name, ndev->mtu);
      //	rxe_set_mtu(rxe, ndev->mtu, net_to_port(ndev));
      //}
      break;
   
   case NETDEV_REBOOT:
   case NETDEV_CHANGE:
   case NETDEV_GOING_DOWN:
   case NETDEV_CHANGEADDR:
   case NETDEV_CHANGENAME:
   case NETDEV_FEAT_CHANGE:
   default:
   	pr_info("rxe_net: ignoring netdev event = %ld for %s\n",
   		event, ndev->name);
   	break;
   }
   spin_unlock_bh(&vnet_info_lock);

out:
   return NOTIFY_OK;
}

static int rxe_net_rcv(struct sk_buff *skb,
              struct net_device *ndev,
              struct packet_type *ptype,
              struct net_device *orig_dev)
{
   int rc = 0;

   /* TODO: We can receive packets in fragments. For now we
    * linearize and it's costly because we may copy a lot of
    * data. We should handle that case better. */
   if (skb_linearize(skb))
      goto drop;
   
#if 0
   /* Error injector */
   {
      static int x = 8;
      static int counter;
      counter++;
      
      if (counter == x) {
         x = 13-x; /* 8 or 5 */
         counter = 0;
         pr_debug("dropping one packet\n");
         goto drop;
      }
   }
#endif
   
   skb = skb_share_check(skb, GFP_ATOMIC);
   if (!skb) {
      /* still return null */
      goto out;
   }
   
   rc = NF_HOOK(NFPROTO_RXE, NF_RXE_IN, skb, ndev, NULL, handle_rx);

out:
   return rc;

drop:
   kfree_skb(skb);
   return 0;
}

static struct packet_type rxe_packet_type = {
   .func = rxe_net_rcv,
};

static struct notifier_block vrxe_net_notifier = {
   .notifier_call = rxe_notify,
};

static struct miscdevice vhost_rxe_misc = {
	MISC_DYNAMIC_MINOR,
	"vhost-rxe",
	&vhost_rxe_fops,
};

static int vhost_rxe_init(void)
{
   int err = 0;
   spin_lock_init(&vnet_info_lock);
   rxe_packet_type.type = cpu_to_be16(rxe_eth_proto_id);
   dev_add_pack(&rxe_packet_type);
   err = register_netdevice_notifier(&vrxe_net_notifier);   
   rcv_wq = create_workqueue("recieve_queue");  
   pr_warn("rxe virtual host driver loaded\n");
   return misc_register(&vhost_rxe_misc);
}
module_init(vhost_rxe_init);

static void vhost_rxe_exit(void)
{
   unregister_netdevice_notifier(&vrxe_net_notifier);
   dev_remove_pack(&rxe_packet_type);
   pr_warn("rxe virtual host driver removed\n");
   flush_workqueue(rcv_wq);
   destroy_workqueue(rcv_wq);
   misc_deregister(&vhost_rxe_misc);
}
module_exit(vhost_rxe_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Robert Lancaster");
MODULE_DESCRIPTION("Host kernel accelerator for virtio rxe");

