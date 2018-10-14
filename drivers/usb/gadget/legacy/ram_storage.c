
#define DEBUG
#include <linux/kernel.h>
#include <linux/usb/ch9.h>
#include <linux/module.h>
#include <linux/usb/composite.h>
#include "ram_storage.h"

USB_GADGET_COMPOSITE_OPTIONS();

#define DRIVER_NAME	"g_ram_storage"
#define DRIVER_DESC	"Ram Storage Gadget"
#define RSG_VID		0x123
#define RSG_PID		0x123
#define SZ_MAX_PACKET	512

static struct usb_function_instance *func_inst_rsg;
static struct usb_function *func_rsg;

/* USB_DT_DEVICE: Device descriptor */
struct usb_device_descriptor rsg_dev_desc = {
	.bLength		= sizeof(struct usb_device_descriptor),
	.bDescriptorType	= USB_DT_DEVICE,
	.bDeviceClass		= USB_CLASS_VENDOR_SPEC,
	.idVendor		= RSG_VID,
	.idProduct		= RSG_PID,
	//.iManufacturer		= "prityaa",
	.bNumConfigurations	= 1,
	//.bMaxPacketSize0	= SZ_MAX_PACKET,
};

static struct usb_configuration rsg_config_driver = {
	.label = DRIVER_DESC,
	.bConfigurationValue = 1,
	.iConfiguration = 0,
	.bmAttributes = USB_CONFIG_ATT_SELFPOWER,
	.MaxPower = CONFIG_USB_GADGET_VBUS_DRAW,
};

static struct usb_string strings_dev[] = {
	[USB_GADGET_MANUFACTURER_IDX].s = "prityaa",
	[USB_GADGET_PRODUCT_IDX].s = DRIVER_DESC,
	[USB_GADGET_SERIAL_IDX].s = "98765",
	{  } /* end of list */
};

static struct usb_gadget_strings stringtab_dev = {
	.language       = 0x0409,       /* en-us */
	.strings        = strings_dev,
};

static struct usb_gadget_strings *dev_strings[] = {
        &stringtab_dev,
	NULL,
};

static int rsg_config_bind(struct usb_configuration *c)
{
	int status;

	func_rsg = usb_get_function(func_inst_rsg);
	if (IS_ERR(func_rsg))
		return PTR_ERR(func_rsg);

	status = usb_add_function(c, func_rsg);
	if (status < 0)
		usb_put_function(func_rsg);

	return status;
}

static int rsg_bind(struct usb_composite_dev *cdev)
{
	struct urs_opts *urs_opts;
	struct device *dev = &cdev->gadget->dev;
	char ret;

	func_inst_rsg = usb_get_function_instance("rsg");
	pr_debug("%s : func_inst_rsg = %p\n", __func__, func_inst_rsg);
	if (IS_ERR(func_inst_rsg))
		return PTR_ERR(func_inst_rsg);

	urs_opts = container_of(func_inst_rsg, struct urs_opts, func_inst);

	pr_debug("%s : ids_tab", __func__);
	if ((ret = usb_string_ids_tab(cdev, strings_dev)) < 0) {
		dev_err(dev, "%s : fail to alloc unused str IDs\n", __func__);
		goto rsg_bind_err;
	}

	pr_debug("%s : rewriting dev_desc\n", __func__);
	rsg_dev_desc.iManufacturer = strings_dev[USB_GADGET_MANUFACTURER_IDX].id;
	rsg_dev_desc.iProduct = strings_dev[USB_GADGET_PRODUCT_IDX].id;
	rsg_dev_desc.iSerialNumber = strings_dev[USB_GADGET_SERIAL_IDX].id;

	pr_debug("%s : usb_add_config", __func__);
	if ((ret = usb_add_config(cdev, &rsg_config_driver, rsg_config_bind))) {
		dev_err(dev, "%s : failed to add  config\n", __func__);
		goto rsg_bind_err;
	}

	pr_debug("%s : usb_composite_overwrite_options", __func__);
	usb_composite_overwrite_options(cdev, &coverwrite);
	dev_info(dev, DRIVER_NAME ", Description: " DRIVER_DESC "\n");

	return 0;

rsg_bind_err:
	usb_put_function_instance(func_inst_rsg);
	return ret;
}

static int rsg_unbind(struct usb_composite_dev *cdev)
{
	pr_debug("%s : putting fun\n", __func__);
	if (!IS_ERR_OR_NULL(func_rsg))
		usb_put_function(func_rsg);

	if (!IS_ERR_OR_NULL(func_inst_rsg))
		usb_put_function_instance(func_inst_rsg);

	return 0;
}

static struct usb_composite_driver rsg_comp_drv = {
	.name		= DRIVER_NAME,
	.dev		= &rsg_dev_desc,
	.max_speed	= USB_SPEED_SUPER,
	.strings	= dev_strings,
	.needs_serial	= 1,
	.bind		= rsg_bind,
	.unbind		= rsg_unbind,
};

static int __init rsg_init(void)
{
	pr_debug("%s : composite driver\n", __func__);
	return usb_composite_probe(&rsg_comp_drv);
}
module_init(rsg_init);

static void __exit rsg_exit(void)
{
	pr_debug("%s : composite driver\n", __func__);
	usb_composite_unregister(&rsg_comp_drv);
}
module_exit(rsg_exit);

//module_usb_composite_driver(rsg_comp_drv);

MODULE_AUTHOR("prityaa");
MODULE_DESCRIPTION("RAM STORAGE");
MODULE_LICENSE("GPL");
