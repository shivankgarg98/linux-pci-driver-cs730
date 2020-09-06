/*
 * Copyright (C) 2015 Kevin Grandemange
 * Copyright (C) 2020 Shivank Garg
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/cdev.h> /* cdev_ */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/mm.h>

#define PCI_CRYPTO_VENDOR 0x1234
#define PCI_CRYPTO_DEVICE 0xdeba
#define PCI_CRYPTO_SUBVENDOR 0x1af4
#define PCI_CRYPTO_SUBDEVICE 0x1100
#define IO_IRQ_ACK 0x64
#define IO_IRQ_STATUS 0x24
#define DEVNAME "CryptoCard"

DECLARE_WAIT_QUEUE_HEAD(wait_queue_crypto);

static struct pci_driver cryptocard;
atomic_t device_opened;
void *kbufdma;
static int isDMA;
static int isInterrupt;
dma_addr_t handle;
int wait_flag = 0;
struct crypto_mem {
    const char *name;
    void __iomem *start;
    unsigned long size;
};
struct crypto_char {
    dev_t major;
    struct cdev cdev;
};
struct crypto_info {
    struct crypto_mem mem;
    struct crypto_char char_dev;
    u8 irq;
};

static struct class *char_class;
struct crypto_info *info;
static int ch_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}


static ssize_t isDMA_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{	
	return sprintf(buf, "%d\n", isDMA);	
}

static ssize_t isDMA_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
        sscanf(buf,"%d",&isDMA);
	//printk("isDMA_set, %c, %d\n", *buf, isDMA);
	return count;
}
static ssize_t isInterrupt_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{	
	return sprintf(buf, "%d\n",isInterrupt);	
}

static ssize_t isInterrupt_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
        sscanf(buf,"%d",&isInterrupt);
	//printk("isInterrupt_set, %c, %d\n", *buf, isInterrupt);
	return count;
}
static struct kobj_attribute isDMA_attribute = __ATTR(isDMA, 0664, isDMA_show, isDMA_store);
static struct kobj_attribute isInterrupt_attribute = __ATTR(isInterrupt, 0664, isInterrupt_show, isInterrupt_store);

static struct attribute *attrs[] = {
	&isDMA_attribute.attr,
	&isInterrupt_attribute.attr,
	NULL,
};
static struct attribute_group isDMA_attr_group = {
	.attrs = attrs,
	.name = "CryptoSys",
};

static int ch_open(struct inode *inode, struct file *file)
{
	file->private_data = info;
	
	atomic_inc(&device_opened);
        try_module_get(THIS_MODULE);
	
        //printk(KERN_INFO "Device opened successfully\n");
        return 0;
}

static int ch_release(struct inode *inode, struct file *file)
{
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        //printk(KERN_INFO "Device closed successfully\n");
        return 0;
}

static ssize_t ch_read(struct file *filep, char __user *buf, size_t count, loff_t *ppos)
{
	struct crypto_info *info = (struct crypto_info *)filep->private_data;
	u32 offset = *ppos;
	int err = 0;
	u32 data1;
	u64 data2;
	u32 __user *tmp1;
	u64 __user *tmp2;
	if (isDMA == 0) {
		//printk("MMIO path\n");
		switch (offset) {
		case 0x20:
		case 0x24:
			tmp1 = (u32 __user *) buf;
			data1 = readl(info->mem.start+offset);
                	if (copy_to_user(tmp1, &data1, 4))
                        	return -EFAULT;
			return 4;
		case 0xa8:
			if(copy_to_user(buf,info->mem.start+offset,count))
				return -EFAULT;
			return count;
		default:
			printk("Unknown Offset\n");
			return -EFAULT;
		}
	} else {
		switch (offset) {
		case 0xa0:
			tmp2 = (u64 __user *) buf;
			data2 = readq(info->mem.start+offset);
                	if (copy_to_user(tmp2, &data2, 8))
                        	return -EFAULT;
			return 8;
		case 0xa8:
			tmp2 = (u64 __user *) buf;
			if(copy_to_user(tmp2,kbufdma,count))
				return -EFAULT;
			return count;
		default:
			printk("Unknown Offset\n");
			return -EFAULT;
		}

	} 
	return err;
}
static ssize_t ch_write(struct file *filep, const char __user *buf, size_t count, loff_t *ppos)
{
	struct crypto_info *info = (struct crypto_info *)filep->private_data;
	
	u32 offset = *ppos;
	int err = 0;
	u32 data1;
	u64 data2;
	const u32 __user *tmp1;
	const u64 __user *tmp2; 
	if (isDMA == 0) {
		switch (offset) {
		case 0x08:
		case 0x0c:
		case 0x20:
			tmp1 = (const u32 __user *)buf;
			if(copy_from_user(&data1,tmp1,4)) {
				return -EFAULT;
				break;
			}	
			writel(data1, info->mem.start + offset);
			return 4;
		case 0x80:
			tmp2 = (const u64 __user *)buf;
			if(copy_from_user(&data2,tmp2,8))
				return -EFAULT;
			writeq(data2,info->mem.start+offset);
			if(isInterrupt) {
				wait_flag = 1;
				wait_event_interruptible(wait_queue_crypto,wait_flag==0);
			}
			return 8;
		case 0xa8:
			if (copy_from_user(info->mem.start+offset,buf,count))
				return -EFAULT;
			return count;
		default:
			printk("MMIO: Unknown Offset\n");
			return -EFAULT;
		}
	} else {
		switch (offset) {
		case 0x08:
			tmp1 = (const u32 __user *)buf;
			if(copy_from_user(&data1,tmp1,4)) {
				return -EFAULT;
			}	
			writel(data1, info->mem.start + offset);
			return 4;
		case 0x90:
			data2 = (u64)handle;
			writeq(data2,info->mem.start+offset); /*DMA address*/
			return 8;
		case 0x98:
			tmp2 = (const u64 __user *)buf;
			if(copy_from_user(&data2,tmp2,8))
				return -EFAULT;
			writeq(data2,info->mem.start+offset);
			return 8;
		case 0xa0:
			tmp2 = (const u64 __user *)buf;
			if(copy_from_user(&data2,tmp2,8))
				return -EFAULT;
			writeq(data2,info->mem.start+offset);
			if(isInterrupt) {
				wait_flag = 1;
				wait_event_interruptible(wait_queue_crypto,wait_flag == 0);		
			}
			return 8;
		case 0xa8:
			if(copy_from_user(kbufdma,buf,count))
				return -EFAULT;	
			return count;
		default:
			printk("DMA: unkown offset\n");
			return -EFAULT;
		}
	
	}
	return err;
}
/*static int ch_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &my_vm_ops;
	vma->vm_private_data = filep->private_data;
	
	return 0;
}
*/
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = ch_read,
	.write = ch_write,
	.open = ch_open,
//	.mmap = ch_mmap,
	.release = ch_release,
};


static irqreturn_t cryptocard_handler(int irq, void *dev_info)
{
    struct crypto_info *info = (struct crypto_info *)dev_info;
    u32 irq_status;
    irqreturn_t ret;

    if (irq == info->irq) { /*major*/
	irq_status = ioread32(info->mem.start+IO_IRQ_STATUS);
       	
	if (irq_status == 0x100) {
		/*DMA*/
		wait_flag = 0;
		wake_up_interruptible(&wait_queue_crypto);
		//pr_info("interrupt irq = %d dev = %d irq_status = %llx\n",
		//	info->irq, irq, (unsigned long long)irq_status);
       		
	}
	else if (irq_status == 0x001) {
		/*MMIO*/
		wait_flag = 0;
		wake_up_interruptible(&wait_queue_crypto);
		//pr_info("interrupt irq = %d dev = %d irq_status = %llx\n",
		//	info->irq, irq, (unsigned long long)irq_status);
	}
	iowrite32(irq_status,info->mem.start+IO_IRQ_ACK);
	ret = IRQ_HANDLED;
    } else {
	ret = IRQ_NONE;
    }

    return ret;
}


static int cryptocard_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err = 0;
	struct device *dev;
        dev_t dev_num;
	
	info = kzalloc(sizeof(struct crypto_info), GFP_KERNEL);
	
	if (!info)
		return -ENOMEM;
	
	err = pci_enable_device_mem(pdev);
	if(err)
		goto failure_pci_enable;
//	pr_alert("enabled device\n");

	err = pci_request_selected_regions(pdev,0,"PCI-MMIO");
        if(err)
		goto failure_pci_regions;
//	pr_alert("requested regions\n");
	
	info->mem.name = "cry-MMIO";	
	info->mem.start = pci_iomap(pdev, 0, pci_resource_len(pdev, 0));
	info->mem.size = pci_resource_len(pdev,0);
	
	if(IS_ERR(info->mem.start))
		err = PTR_ERR(info->mem.start);
	if(err) {
		if(info->mem.start)
			iounmap(info->mem.start);
		goto failure_ioremap;
	}
//	pr_alert("remaped addr for kernel uses\n");

	err = alloc_chrdev_region(&dev_num,0,1,"crypto-MMIO");
	if (err)
		goto failure_alloc_chrdev_region;
	info->char_dev.major = MAJOR(dev_num);
	cdev_init(&info->char_dev.cdev,&fops);
	
	err = cdev_add(&info->char_dev.cdev, MKDEV(info->char_dev.major, 0),1);
	if(err)
		goto failure_cdev_add;
	dev = device_create(char_class, &pdev->dev, MKDEV(info->char_dev.major,0),NULL,"mycryptochar%d",0);
	if(IS_ERR(dev))
		err = PTR_ERR(dev);
	if(err) {
		pr_alert("ERROR: device_create failed\n");
		goto failure_device_create;
	}
	//dev_info(&pdev->dev, "claimed by crypto-char\n");

	if (pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &info->irq))
        	goto failure_irq;	
	if (devm_request_irq(&pdev->dev,info->irq,cryptocard_handler,IRQF_SHARED,cryptocard.name,(void *)info))
		goto failure_irq;

	kbufdma = dma_zalloc_coherent(&pdev->dev,4096*8,&handle,GFP_KERNEL);
	if (!kbufdma)
		goto failure_irq;
//	printk("dma handle: %llx",handle);	
	pci_set_drvdata(pdev,info);
	/*u32 kbuf;
	u32 kbuf2;
	kbuf = ioread32(info->mem.start);
	printk("%x : identification no.\n",kbuf);
	kbuf = 0x11223344u;
	iowrite32(kbuf, info->mem.start+0x04);
	kbuf2 = ioread32(info->mem.start+0x04);
	printk("%x : liveness check\n",kbuf2);
	*/
//	pr_alert("End of the method \n");
	return 0;
failure_irq:
	pr_alert("IRQ or DMA have a problem\n");	
	device_destroy(char_class, MKDEV(info->char_dev.major,0));
failure_device_create:
	cdev_del(&info->char_dev.cdev);
failure_cdev_add:
	unregister_chrdev_region(MKDEV(info->char_dev.major, 0), 0);
failure_alloc_chrdev_region:
	iounmap(info->mem.start);
failure_ioremap:
	pci_release_selected_regions(pdev,pci_select_bars(pdev, 0));
failure_pci_regions:
	pci_disable_device(pdev);
failure_pci_enable:
	kfree(info);
	
	return err;
}

static void cryptocard_remove(struct pci_dev *pdev)
{
    struct crypto_info *info = pci_get_drvdata(pdev);

    device_destroy(char_class, MKDEV(info->char_dev.major,0));

    cdev_del(&info->char_dev.cdev);
    unregister_chrdev_region(MKDEV(info->char_dev.major,0),1);
    iounmap(info->mem.start);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
    dma_free_coherent(&pdev->dev,4096*8,kbufdma,handle);
    //pr_info("cryptocard remove\n");
    kfree(info);
}

static struct pci_device_id cryptocard_ids[] = {
    
    { PCI_DEVICE(PCI_CRYPTO_VENDOR, PCI_CRYPTO_DEVICE) },
    { 0, },
};

static struct pci_driver cryptocard = {
    .name = DEVNAME,
    .id_table = cryptocard_ids,
    .probe = cryptocard_probe,
    .remove = cryptocard_remove,
};

static int __init crypto_init(void) {
	int err = 0;
	char_class = class_create(THIS_MODULE,"mycryptochar");
	char_class->dev_uevent = ch_uevent;
	if (IS_ERR(char_class)) {
		err = PTR_ERR(char_class);
		return err;
	}
	err = pci_register_driver(&cryptocard);
	if (err)
		goto failure_register_driver;
	err = sysfs_create_group(kernel_kobj, &isDMA_attr_group);
	if(unlikely(err)){
//		printk(KERN_INFO "CryptoCard: can't create sysfs\n");
		goto failure_sysfs;
	}
	
	atomic_set(&device_opened,0);
		
	return 0;

failure_sysfs:
	pci_unregister_driver(&cryptocard);
failure_register_driver:
	class_destroy(char_class);
	
	return err;

}
static void __exit crypto_exit(void) {
	pci_unregister_driver(&cryptocard);
	class_destroy(char_class);
	sysfs_remove_group(kernel_kobj, &isDMA_attr_group);
}

module_init(crypto_init);
module_exit(crypto_exit);

MODULE_DEVICE_TABLE(pci, cryptocard_ids);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CryptoCard");
MODULE_AUTHOR("Shivank Garg");
