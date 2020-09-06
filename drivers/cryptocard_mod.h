#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include  <asm/tlbflush.h>
#include <linux/uaccess.h>
#include <linux/device.h>


#define DEVNAME "CryptoCard"


extern struct attribute_group crypto_attr_group;
