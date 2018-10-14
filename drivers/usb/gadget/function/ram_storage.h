
#ifndef __F_RAM_H__
#define __F_RAM_H__

struct urs_opts {
	struct usb_function_instance    func_inst;
	struct mutex                    lock;
	int                             refcnt;
};

#endif
