/*
 * main.c -- the bare scull char module
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/cdev.h>

#include <linux/uaccess.h>	/* copy_*_user */


/*
 * Our parameters which can be set at load time.
 */

int scull_major = 0;
int scull_minor = 0;
int scull_nr_devs = 1;	/* number of bare scull devices */
int scull_quantum = 8000;

module_param(scull_quantum, int, S_IRUGO);

MODULE_AUTHOR("Alessandro Rubini, Jonathan Corbet");
MODULE_LICENSE("Dual BSD/GPL");

unsigned char *data;   /*Pointer to store the data */
int size;             /* size of data stored in the pointer */
struct cdev cdev;	  /* Char device structure		*/


int scull_open(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "Opening device");
	return 0;          /* success */
}

int scull_release(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "Closing device");
	return 0;
}

ssize_t scull_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
	printk(KERN_INFO "Reading device");
	return 0;
}


ssize_t scull_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
	printk(KERN_INFO "Writing device");
	return count;
}


struct file_operations scull_fops = {
	.owner =    THIS_MODULE,
	.read =     scull_read,
	.write =    scull_write,
	.open =     scull_open,
	.release =  scull_release,
};

void scull_cleanup_module(void)
{
	dev_t devno = MKDEV(scull_major, scull_minor);

	printk(KERN_INFO "Exit Scull Module");

	/* Get rid of our char dev entries */
	cdev_del(&cdev);

	/* cleanup_module is never called if registering failed */
	unregister_chrdev_region(devno, scull_nr_devs);
}


/*
 * Set up the char_dev structure for this device.
 */
static void scull_setup_cdev(void)
{
	int err, devno = MKDEV(scull_major, scull_minor);
    
	cdev_init(&cdev, &scull_fops);
	cdev.owner = THIS_MODULE;
	err = cdev_add (&cdev, devno, 1);


	/* Fail gracefully if need be */
	if (err)
		printk(KERN_NOTICE "Error %d adding scull", err);

}


int scull_init_module(void)
{
	int result;
	dev_t dev = 0;

	printk(KERN_INFO "Init the SCULL Module");
	/*
	 * Get a range of minor numbers to work with, asking for a dynamic
	 * major unless directed otherwise at load time.
	 */
	result = alloc_chrdev_region(&dev, scull_minor, scull_nr_devs,
				     "scull");
	scull_major = MAJOR(dev);
	if (result < 0) {
		printk(KERN_WARNING "scull: can't get major %d\n", scull_major);
		return result;
	}

	scull_setup_cdev();

	return 0; /* succeed */
}

module_init(scull_init_module);
module_exit(scull_cleanup_module);
