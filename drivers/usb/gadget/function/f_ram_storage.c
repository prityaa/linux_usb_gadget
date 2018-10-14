
#define DEBUG
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kfifo.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/usb/composite.h>
#include <linux/usb/ch9.h>

#include <linux/err.h>
#include "ram_storage.h"
#include "u_f.h"

#define FUNCTION_NAME	"rsg"
#define MAX_LEN		512
#define EP_OUT_FIFO_SIZE        4096

static dev_t dev;
static struct cdev *chr_dev;
static struct class *cls;
static struct usb_function_driver rsgusb_func;
static struct file_operations rsg_fops;

static STRUCT_KFIFO_REC_2(EP_OUT_FIFO_SIZE) fifo_out;

struct rs_dev {
	wait_queue_head_t tx_queue, rx_queue;
	char tx_pending, rx_wakeup;

	struct usb_ep *in_ep, *out_ep;
	struct usb_request *out_req, *in_req;
	struct usb_function func;

	struct cdev *chr_dev;

	spinlock_t spinlock;
	struct mutex lock;
};

static struct usb_interface_descriptor rs_intf = {
        .bLength = USB_DT_INTERFACE_SIZE,
        .bDescriptorType = USB_DT_INTERFACE,
        .bAlternateSetting = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
};

static struct usb_endpoint_descriptor rs_in_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = USB_DIR_IN,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .bInterval = 0x0A,
};

static struct usb_endpoint_descriptor rs_out_desc = {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = USB_DIR_OUT,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .bInterval = 0x0A,
};

static struct usb_descriptor_header *rs_descs[] = {
	(struct usb_descriptor_header *)&rs_intf,
	(struct usb_descriptor_header *)&rs_out_desc,
	(struct usb_descriptor_header *)&rs_in_desc,
	NULL,
};

static struct usb_endpoint_descriptor hs_rs_in_desc = {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = cpu_to_le16(MAX_LEN),
        .bInterval = 0x0A,
};

static struct usb_endpoint_descriptor hs_rs_out_desc = {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = cpu_to_le16(MAX_LEN),
        .bInterval = 0x0A,
};

static struct usb_descriptor_header *hs_rs_descs[] = {
        (struct usb_descriptor_header *)&rs_intf,
        (struct usb_descriptor_header *)&hs_rs_out_desc,
        (struct usb_descriptor_header *)&hs_rs_in_desc,
        NULL,
};

static void rs_complete(struct usb_ep *ep, struct usb_request *req)
{
        unsigned long flags;
        struct rs_dev *rs = (struct rs_dev *)ep->driver_data;

        /* driver_data will be null if ep has been disabled */
        if (!rs)
                return;

        if (req->status)
                pr_err("[KS]%s: status = %d\n", __func__, req->status);

        if (ep == rs->out_ep) {
                kfifo_in(&fifo_out, req->buf, req->actual);
                spin_lock_irqsave(&rs->spinlock, flags);
                rs->rx_wakeup = 1;
                spin_unlock_irqrestore(&rs->spinlock, flags);
                wake_up_interruptible(&rs->rx_queue);
        } else if (ep == rs->in_ep) {
                rs->tx_pending = 0;
                wake_up(&rs->tx_queue);
        }
}

static void disable_ep(struct usb_ep *ep)
{
        int value;

        if (!ep->driver_data)
                return;

        value = usb_ep_disable(ep);
        if (value < 0)
                pr_err("[KS]disable %s --> %d\n", ep->name, value);

        ep->driver_data = NULL;
}

static void disable_rs_ep(struct usb_function *f)
{
        struct rs_dev *rs = container_of(f, struct rs_dev, func);

        disable_ep(rs->in_ep);
        disable_ep(rs->out_ep);
}

void rs_free_ep_req(struct usb_ep *ep, struct usb_request *req)
{
        kfree(req->buf);
        usb_ep_free_request(ep, req);
}

#if 0
static struct usb_request *alloc_ep_req(struct usb_ep *ep, int len, int default_len)
{
	struct usb_request      *req;

	req = usb_ep_alloc_request(ep, GFP_ATOMIC);
	if (req) {
		req->length = len ?: default_len;
		req->buf = kmalloc(req->length, GFP_ATOMIC);
		if (!req->buf) {
			usb_ep_free_request(ep, req);
			req = NULL;
		}
	}
	return req;
}
#endif

static inline struct usb_request *rs_alloc_ep_req(struct usb_ep *ep, int len)
{
        return alloc_ep_req(ep, MAX_LEN);
}

static int rs_start_ep(struct usb_composite_dev *cdev,
                             struct rs_dev *rs, struct usb_ep *ep)
{
        int status = -1;
        struct usb_request *req;

        if (!ep)
                return status;

        usb_ep_disable(ep);

        status = config_ep_by_speed(cdev->gadget, &(rs->func), ep);
        if (status)
                return status;

        status = usb_ep_enable(ep);
        if (status < 0)
                return status;

        ep->driver_data = rs;

        req = rs_alloc_ep_req(ep, 0);
        if (!req) {
                status = -ENOMEM;
                goto start_err;
        }

        if (ep == rs->in_ep) {
                rs->in_req = req;
                return status;
        }

        rs->out_req = req;
        req->context = rs;
        req->complete = rs_complete;

	/**
	  * send usb ep queue to listen to host packet
	  */
        status = usb_ep_queue(ep, req, GFP_ATOMIC);
        if (status) {
                pr_err("%s: start %s --> %d\n", __func__, ep->name, status);
                rs_free_ep_req(ep, req);
                goto start_err;
        }

        return status;

start_err:
        usb_ep_disable(ep);
        ep->driver_data = NULL;

        return status;
}


static int enable_rs_ep(struct usb_composite_dev *cdev,
				struct rs_dev *rs, int alt)
{
        int result;

        result = rs_start_ep(cdev, rs, rs->in_ep);
	pr_debug("%s : start_ep IN : result = %d\n", __func__, result);
        if (result < 0)
                return result;

        result = rs_start_ep(cdev, rs, rs->out_ep);
	pr_debug("%s : start_ep OUT : result = %d\n", __func__, result);
        if (result < 0)
                goto fail;

        return result;

fail:
        usb_ep_disable(rs->in_ep);
        rs->in_ep->driver_data = NULL;

        return result;
}

static int rs_set_alt(struct usb_function *f, unsigned int intf,
                            unsigned int alt)
{
        struct rs_dev *rs = container_of(f, struct rs_dev, func);
        struct usb_composite_dev *cdev = f->config->cdev;

        if (rs->in_ep->driver_data)
                disable_rs_ep(f);

        return enable_rs_ep(cdev, rs, alt);
}

static int rs_setup(struct usb_function *f,
			  const struct usb_ctrlrequest *ctrl)
{
        return 0;
}

static int rs_bind(struct usb_configuration *c, struct usb_function *f)
{
	int id;
	int ret;
	struct rs_dev *rs = container_of(f, struct rs_dev, func);
	struct usb_composite_dev *cdev = c->cdev;

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	pr_debug("%s: usb_interface_id = %d\n", __func__, id);
	if (id < 0)
		return id;

	rs_intf.bInterfaceNumber = id;

	/* allocate bulk endpoints */
	rs->in_ep = usb_ep_autoconfig(cdev->gadget, &rs_in_desc);
	pr_debug("%s : rs->in_ep = %p\n", __func__, rs->in_ep);
	if (!rs->in_ep)
		goto autoconf_fail;

	rs->in_ep->driver_data = cdev;        /* claim */

	rs->out_ep = usb_ep_autoconfig(cdev->gadget, &rs_out_desc);
	pr_debug("%s : out_ep = %p\n", __func__, rs->out_ep);
	if (!rs->out_ep)
		goto autoconf_fail;

	rs->out_ep->driver_data = cdev;       /* claim */

	/* support high speed hardware */
	hs_rs_in_desc.bEndpointAddress = rs_in_desc.bEndpointAddress;
	hs_rs_out_desc.bEndpointAddress = rs_out_desc.bEndpointAddress;

	ret = usb_assign_descriptors(f, rs_descs, hs_rs_descs,
			NULL, NULL);
	pr_debug("%s : ret usb_assign_descriptors = %d\n", __func__, ret);
	if (ret)
		return ret;

	mutex_init(&rs->lock);
	spin_lock_init(&rs->spinlock);
	init_waitqueue_head(&rs->tx_queue);
	init_waitqueue_head(&rs->rx_queue);
#if 0
	rs->chr_dev = cdev_alloc();
	rs->chr_dev->owner = THIS_MODULE;
	rs->chr_dev->fops = &rsg_fops;
#endif
	cdev_init(rs->chr_dev, &rsg_fops);

	if ((ret = cdev_add(rs->chr_dev, dev, 0))) {
		pr_err("%s : fail to add char dev\n", __func__);
		goto unregister_chrdev;
	}

	cls = class_create(THIS_MODULE, FUNCTION_NAME);
	pr_debug("%s : creating class %p\n", __func__, cls);
	if (IS_ERR(cls)) {
		pr_err("%s: failed to class create\n", __func__);
		ret = PTR_ERR(cls);
		goto cdev_del;
	}

	pr_debug("%s : creating device\n", __func__);
	if (IS_ERR(device_create(cls, NULL, dev, NULL, FUNCTION_NAME))) {
		pr_err("%s : fail to create device\n", __func__);
		ret = -ENODEV;
		goto cls_destroy;
	}

	pr_info("%s : %s speed %s: IN/%s, OUT/%s\n", __func__,
		gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
			f->name, rs->in_ep->name, rs->out_ep->name);

	return 0;

autoconf_fail:
	pr_err("%s: %s: can't autoconfigure on %s\n", __func__,
			f->name, cdev->gadget->name);
	return -ENODEV;

cls_destroy:
	class_destroy(cls);

cdev_del:
	cdev_del(rs->chr_dev);

unregister_chrdev:
	unregister_chrdev_region(dev, 1);

unregister_fun:
	usb_function_unregister(&rsgusb_func);

	return ret;
}

static void rs_storage_free(struct usb_function_instance *fi)
{
        struct rs_opts *opts;

        opts = container_of(fi, struct rs_opts, func_inst);
        kfree(opts);
}

static struct usb_function_instance *rsg_inst_alloc(void)
{
	struct rs_opts *alloc_rs_opts;

	alloc_rs_opts = kzalloc(sizeof(*alloc_rs_opts), GFP_KERNEL);
	if (!alloc_rs_opts) {
		pr_err("Failed to alloc mem for alloc_rs_opts\n");
		return ERR_PTR(-ENOMEM);
	}

	mutex_init(&alloc_rs_opts->lock);
	alloc_rs_opts->func_inst.free_func_inst = rs_storage_free;

	pr_debug("%s : gadget functio inst\n", __func__);
	return &alloc_rs_opts->func_inst;
}

static void rs_free_func(struct usb_function *f)
{
        struct rs_opts *opts;
        struct rs_dev *rs = container_of(f, struct rs_dev, func);

	pr_debug("%s : rs = %p\n", __func__, rs);
        opts = container_of(f->fi, struct rs_opts, func_inst);

        mutex_lock(&rs->lock);
        opts->refcnt--;
        mutex_unlock(&rs->lock);

        usb_free_all_descriptors(f);
        kfree(rs);
}

struct usb_function *rsg_func_alloc(struct usb_function_instance *inst)
{
	struct rs_dev *rs_dev;
	struct rs_opts *rs_opts;

	rs_dev = kzalloc(sizeof(*rs_dev), GFP_KERNEL);
	pr_debug("%s : rs = %p\n", __func__, rs_dev);
	if (!rs_dev) {
		pr_err("%s : Failed to alloc mem for rs\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	/**
	   You have a pointer "inst" that points in the middle of a
	   structure (and you know that is a pointer to
	   the field "func_inst" but you want to retrieve the entire
	   structure "rs_opts,".
	   So, you calculate the offset of the filed two in the structure.
	*/
	rs_opts = container_of(inst, struct rs_opts, func_inst);

	rs_dev->func.name = "rs storage";
	rs_dev->func.bind = rs_bind;
	/* since legacy unbind calls free func,
	   no need of using over here

	   rs_dev->func.unbind = rs_unbind;
	*/
	rs_dev->func.set_alt = rs_set_alt;
	rs_dev->func.setup = rs_setup;
	rs_dev->func.free_func = rs_free_func;
	rs_dev->chr_dev = chr_dev;

	pr_debug("%s : called function ", __func__);
	return &rs_dev->func;
}

static ssize_t rs_read (struct file *file,
			 char __user *buf, size_t cnt, loff_t *pos)
{
	struct rs_dev *rs = file->private_data;
	int copied = 0, ret;

	pr_debug("%s : reading usb data %p\n", __func__, rs);

	if (access_ok(VERIFY_WRITE, buf, cnt))
		return -EFAULT;

	spin_lock(&rs->spinlock);

	while (!rs->rx_wakeup) {
		spin_unlock(&rs->spinlock);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		pr_debug("%s : waiting to data to come\n", __func__);
		if (wait_event_interruptible(rs->rx_queue, rs->rx_wakeup))
			return -ERESTARTSYS;

		spin_lock(&rs->spinlock);
	}

	rs->rx_wakeup = 0;
	spin_unlock(&rs->spinlock);

	cnt = kfifo_peek_len(&fifo_out);

	ret = kfifo_to_user(&fifo_out, buf, cnt, &copied);
	if (ret < 0)
		pr_err("%s : kfifo_to_user err ret %d and copied %d\n",
				__func__, ret, copied);

	rs->out_req->length = MAX_LEN;

	ret = usb_ep_queue(rs->out_ep, rs->out_req, GFP_KERNEL);
	if (ret < 0)
		pr_err("%s : falied to usb_ep_queue ret %d\n", __func__, ret);

	return 0;
}

static ssize_t rs_write(struct file *file, const char __user *buf,
			size_t cnt, loff_t *pos)
{
	struct rs_dev *rs = file->private_data;
	struct usb_request *req = rs->in_req;
	int ret;

	pr_debug("%s : rs = %p\n", __func__, rs);

	if (access_ok(VERIFY_WRITE, buf, cnt))
		return -EFAULT;

	mutex_lock(&rs->lock);
	while (rs->tx_pending) {
		mutex_unlock(&rs->lock);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		pr_debug("%s : waiting tx_que\n", __func__);
		if (wait_event_interruptible_exclusive(rs->tx_queue,
							!rs->tx_pending)) {
			pr_err("%s : failed to wait for tx_que\n", __func__);
			return -ERESTARTSYS;
		}
		pr_debug("%s : after waiting tx_que\n", __func__);

		mutex_lock(&rs->lock);
	}

	cnt = min_t(unsigned int, cnt, MAX_LEN);

	if ((ret = copy_from_user(rs->in_req->buf, buf, cnt))) {
		mutex_unlock(&rs->lock);
		pr_err("%s : failed to copy all buf\n", __func__);
		return ret;
	}

	rs->tx_pending = 1;
	req->zero = 0;
	req->status = 0;
	req->length = cnt;
	req->context = rs;
	req->complete = rs_complete;

	ret = usb_ep_queue(rs->in_ep, req, GFP_KERNEL);
	if (ret < 0) {
		rs->tx_pending = 0;
		pr_err("%s : in_ep_que is falied\n", __func__);
		wake_up(&rs->tx_queue);
		return ret;
	}

	mutex_unlock(&rs->lock);

	return cnt;
}

static int rs_open(struct inode *inode, struct file *file)
{
	struct rs_dev *rs = container_of(&inode->i_cdev, struct rs_dev, chr_dev);
	pr_debug("%s : file opened %p\n", __func__, rs);

	file->private_data = rs;

	return 0;
}

static int rs_close(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	pr_debug("%s : file released\n", __func__);
        return 0;
}

static struct file_operations rsg_fops = {
	.owner		= THIS_MODULE,
	.open		= rs_open,
	.release	= rs_close,
	.read		= rs_read,
	.write		= rs_write,
};


#if 0
static struct usb_function_driver rsgusb_func = {
	.name = __stringify(rsg),
	.mod  = THIS_MODULE,
	.alloc_inst = rsg_inst_alloc,
	.alloc_func = rsg_func_alloc,
};
MODULE_ALIAS("usbfunc:"__stringify(rsg));

#else
DECLARE_USB_FUNCTION(rsg, rsg_inst_alloc, rsg_func_alloc);
#endif

static int __init rsg_init(void)
{
	char ret;

	pr_debug("%s : register fun\n", __func__);
	ret = usb_function_register(&rsgusb_func);
	if (ret < 0 ) {
		pr_err("%s : falied to register %s fun\n",
				__func__, rsgusb_func.name);
		return ret;
	}

	if ((ret = alloc_chrdev_region(&dev, 0, 1, FUNCTION_NAME)) < 0) {
		pr_err("%s : falied to alloc region\n", __func__);
		goto unregister_fun;
	}

unregister_fun:
	usb_function_unregister(&rsgusb_func);

	return ret;
}
module_init(rsg_init);

static void __exit rsg_exit(void)
{
	usb_function_unregister(&rsgusb_func);
}
module_exit(rsg_exit);

MODULE_AUTHOR("Pritam");
MODULE_LICENSE("GPL");
