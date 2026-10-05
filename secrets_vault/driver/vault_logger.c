// Optional Linux character-device driver for the Capstone demonstration.
// It provides /dev/vault_logger. The user-space vault writes audit events to it;
// the driver prints accepted events to the kernel log (dmesg).
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#define DEVICE_NAME "vault_logger"
#define CLASS_NAME "vault"
#define MAX_MSG 512
static dev_t dev_no;
static struct cdev vault_cdev;
static struct class *vault_class;
static DEFINE_MUTEX(vault_lock);
static char last_msg[MAX_MSG];
static size_t last_len;
static atomic64_t event_count;

static int vault_open(struct inode *inode, struct file *file) { return 0; }
static int vault_release(struct inode *inode, struct file *file) { return 0; }
static ssize_t vault_write(struct file *file, const char __user *buf, size_t len, loff_t *off) {
    size_t n = min(len, (size_t)MAX_MSG - 1);
    if (mutex_lock_interruptible(&vault_lock)) return -ERESTARTSYS;
    if (copy_from_user(last_msg, buf, n)) { mutex_unlock(&vault_lock); return -EFAULT; }
    last_msg[n] = '\0'; last_len = n; atomic64_inc(&event_count);
    pr_info("vault_logger: %s", last_msg);
    mutex_unlock(&vault_lock); return n;
}
static ssize_t vault_read(struct file *file, char __user *buf, size_t len, loff_t *off) {
    ssize_t ret;
    if (*off != 0) return 0;
    if (mutex_lock_interruptible(&vault_lock)) return -ERESTARTSYS;
    if (len < last_len) { mutex_unlock(&vault_lock); return -EINVAL; }
    if (copy_to_user(buf, last_msg, last_len)) { mutex_unlock(&vault_lock); return -EFAULT; }
    ret = last_len; *off += last_len; mutex_unlock(&vault_lock); return ret;
}
static const struct file_operations fops = { .owner=THIS_MODULE, .open=vault_open, .release=vault_release, .write=vault_write, .read=vault_read };
static int __init vault_init(void) {
    int ret = alloc_chrdev_region(&dev_no,0,1,DEVICE_NAME); if(ret) return ret;
    cdev_init(&vault_cdev,&fops); ret=cdev_add(&vault_cdev,dev_no,1); if(ret) goto unregister;
    vault_class=class_create(CLASS_NAME); if(IS_ERR(vault_class)){ret=PTR_ERR(vault_class);goto del;}
    if(IS_ERR(device_create(vault_class,NULL,dev_no,NULL,DEVICE_NAME))){ret=-ENOMEM;goto destroy;}
    atomic64_set(&event_count,0); pr_info("vault_logger: loaded major=%d minor=%d",MAJOR(dev_no),MINOR(dev_no)); return 0;
destroy: class_destroy(vault_class); del: cdev_del(&vault_cdev); unregister: unregister_chrdev_region(dev_no,1); return ret;
}
static void __exit vault_exit(void){device_destroy(vault_class,dev_no);class_destroy(vault_class);cdev_del(&vault_cdev);unregister_chrdev_region(dev_no,1);pr_info("vault_logger: unloaded, events=%lld",atomic64_read(&event_count));}
module_init(vault_init); module_exit(vault_exit);
MODULE_LICENSE("GPL"); MODULE_AUTHOR("Capstone Team"); MODULE_DESCRIPTION("Audit logger character device for encrypted secrets vault");
