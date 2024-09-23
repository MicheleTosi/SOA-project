#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/printk.h>      
#include <linux/ptrace.h>       
#include <linux/syscalls.h>
#include <linux/version.h>

#include "constants.h"
#include "sha256.h"
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michele Tosi");
MODULE_DESCRIPTION("Questo modulo implementa un reference monitor come da specifiche presenti nel file README.md");


// Enumerazione per gli stati del reference monitor
typedef enum reference_monitor_state {
    ON,             // Operazioni abilitate
    OFF,            // Operazioni disabilitate
    REC_ON,         // Può essere riconfigurato in modalita' ON
    REC_OFF,        // Può essere riconfigurato in modalita' OFF
}rm_state;

//nodi path bloccati
typedef struct path_node{
	char *path;
	struct path_node *next;
}path_node;

// Configurazione attuale reference monitor
typedef struct reference_monitor_config {
    rm_state rm_state;                      // Stato corrente reference monitor
    u8 password[PASSWORD_HASH_SIZE];		// Password per riconfigurare il reference monitor
    path_node *head;     					// Lista path non accessibili in scrittura
    spinlock_t lock;
} rm_config;



static int major;

static int rm_open(struct inode *inode, struct file *filp);

static ssize_t rm_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);

static int handler_pre_vfs_open(struct kprobe *p, struct pt_regs *regs);

static int handler_pre_vfs_unlink(struct kprobe *p, struct pt_regs *regs);

static int handler_pre_vfs_mkdir(struct kprobe *p, struct pt_regs *regs);

static int handler_pre_vfs_rmdir(struct kprobe *p, struct pt_regs *regs);

static spinlock_t RM_lock;

struct file_operations my_fops = {
    .owner=THIS_MODULE,
    .open = rm_open,
    .write = rm_write,
};

static struct kprobe kp_vfs_open = {
    .symbol_name=VFS_OPEN,
    .pre_handler= handler_pre_vfs_open,
};

static struct kprobe kp_vfs_rmdir = {
    .symbol_name=VFS_RMDIR,
    .pre_handler= handler_pre_vfs_rmdir,
};

static struct kprobe kp_vfs_mkdir = {
    .symbol_name=VFS_MKDIR,
    .pre_handler= handler_pre_vfs_mkdir,
};

static struct kprobe kp_vfs_unlink = {
    .symbol_name=VFS_UNLINK,
    .pre_handler= handler_pre_vfs_unlink,
};

static rm_config config;

void change_rm_state(rm_state state);


int rm_on(void){

    change_rm_state(ON);

    return 0;
}

int rm_off(void){

    change_rm_state(OFF);

    return 0;
}

int rm_rec_on(void){

    change_rm_state(REC_ON);

    return 0;
}

int rm_rec_off(void){

    change_rm_state(REC_OFF);

    return 0;
}

void change_rm_state(rm_state state){
    
    rm_state current_state=config.rm_state;

    printk("%s: changing reference monitor state\n", MOD_NAME);

    printk("%s: initial state is %d\n", MOD_NAME, current_state);

    if((current_state==OFF || current_state==REC_OFF) && (current_state==ON || current_state==REC_ON)){

        //TODO: attivare il rm

    }else if ((current_state==ON || current_state==REC_ON) && (current_state==OFF || current_state==REC_OFF)){

        //TODO: disattivare il rm

    }

    config.rm_state=state;

    printk("%s: new state is %d\n", MOD_NAME, config.rm_state);

    return;
}

static int rm_open(struct inode *inode, struct file *filp)
{
    return 0;
}

static ssize_t rm_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    return 0;
}

//controllo se nella lista è già presente un path
int check_list(char *abs_path){
	path_node *curr=config.head;
	
	while(curr){
		if(strcmp(curr->path, abs_path)==0){
			printk(KERN_INFO "Path already exist %s\n", abs_path);
			return -EEXIST;
		}
		curr=curr->next;
	}
	
	return 0;
	
}

int add_path(char *path){
	
	char *abs_path=get_absolute_path(path);		//convert path to absolute path
	path_node *new_node;
	int res;
	
	if(!abs_path){
		printk(KERN_ERR "%s: could not resolve absolute path\n", MOD_NAME);
		return -EINVAL;
	}
	
	if(config.rm_state!=REC_ON && config.rm_state!=REC_OFF){
		printk(KERN_ERR "%s: state must be REC_ON or REC_OFF\n", MOD_NAME);
		return -EINVAL;
	}
	
	
	/*if(the_file && strncmp(abs_path, the_file, strlen(the_file))==0){
		printk(KERN_ERR "Error: cannot protect the log file path\n");
		return -EINVAL;
	}*/
	
	spin_lock(&config.lock);
	
	if(!(res=check_list(path))){
		kfree(abs_path);
		return res;
	}
	
	//Creation of the new node
    new_node = kmalloc(sizeof(struct path_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Failed to allocate memory for new node\n");
        spin_unlock(&config.lock);
        kfree(abs_path);
        return -ENOMEM;
    }
    new_node->path = abs_path; 
    new_node->next = config.head;
    config.head = new_node;

    spin_unlock(&config.lock);

    printk(KERN_INFO "Path inserted: %s\n", abs_path);
    
    kfree(abs_path);

    return 0;
	
}

int change_password(char *new_password){

    printk(KERN_INFO "%s: change password", MOD_NAME);
    
    if(!new_password){
    	printk(KERN_ERR "%s: empty password", MOD_NAME);
    	return -EINVAL; 
    }
    
    spin_lock(&RM_lock);
    
    calculate_sha256(new_password, strlen(new_password), config.password);
    
    printk(KERN_INFO "%s: password %s", MOD_NAME, config.password);
    
    printk(KERN_INFO "%s: password aggiornata correttamente", MOD_NAME);
    
    spin_unlock(&RM_lock);
    
    return 0;
    
}

// Funzione di esempio per decidere se bloccare l'operazione
static bool should_block(const char *filename) {
	char *abs_path=get_absolute_path(filename);		//convert path to absolute path

	if(!abs_path){
		printk(KERN_ERR "%s: could not resolve absolute path\n", MOD_NAME);
		return -EINVAL;
	}
	
	if(config.rm_state!=OFF && config.rm_state!=REC_OFF){
		return false;
	}	
	
    if (check_list(abs_path)) {
        return true;
    }
    return false;
}

static int handler_pre_vfs_mkdir(struct kprobe *p, struct pt_regs *regs) {
    struct dentry *dentry = (struct dentry *)regs->si;
    char buf[256];

    // Recupera il nome della directory dal dentry
    dentry_path_raw(dentry, buf, sizeof(buf));

    printk(KERN_INFO "Attempt to create directory: %s\n", buf);

    // Logica per decidere se bloccare l'operazione
    if (should_block(buf)) {
        printk(KERN_INFO "Blocking mkdir of directory: %s\n", buf);
        return -EPERM;
    }

    return 0;
}

static int handler_pre_vfs_rmdir(struct kprobe *p, struct pt_regs *regs) {
    struct dentry *dentry = (struct dentry *)regs->si;
    char buf[256];

    // Recupera il nome della directory dal dentry
    dentry_path_raw(dentry, buf, sizeof(buf));

    printk(KERN_INFO "Attempt to remove directory: %s\n", buf);

    // Logica per decidere se bloccare l'operazione
    if (should_block(buf)) {
        printk(KERN_INFO "Blocking rmdir of directory: %s\n", buf);
        return -EPERM;
    }

    return 0;
}

static int handler_pre_vfs_open(struct kprobe *p, struct pt_regs *regs) {
    const struct path *path = (struct path *)regs->di;
    struct file *file = (struct file *)regs->si;
    char buf[256];

    char *name;

    // Recupera il nome del file dal dentry
    name=dentry_path_raw(path->dentry, buf, sizeof(buf));

    printk("Attempt to open file: %s\n", name);

    // Logica per decidere se bloccare l'operazione
    if (file->f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) {
        if (should_block(buf)) {
            printk(KERN_INFO "Blocking write access to file: %s, file: %s\n", buf, buf);
            return -EPERM;
        }
        printk("Aperto in scrittura: %s\n", name);

    }

    return 0;
}

static int handler_pre_vfs_unlink(struct kprobe *p, struct pt_regs *regs) {
    struct dentry *dentry = (struct dentry *)regs->dx;
    char buf[256];

    // Recupera il nome del file dal dentry
    dentry_path_raw(dentry, buf, sizeof(buf));

    printk(KERN_INFO "Attempt to unlink (delete) file: %s\n", buf);

    // Logica per decidere se bloccare l'operazione
    if (should_block(buf)) {
        printk(KERN_INFO "Blocking unlink of file: %s\n", buf);
        return -EPERM;
    }

    return 0;
}

static int my_module_init(void) {

    int ret;

    major=register_chrdev(0,DEV_NAME,&my_fops);

    if(major<0){
        printk(KERN_ERR "register_chrdev failed: %d\n", major);
        return major;
    }

    printk(KERN_INFO "%s: device \"%s\" registered with major number %d\n",MOD_NAME,DEV_NAME, major);

    // Calcola l'hash SHA-256 della password
    ret = calculate_sha256("password", strlen("password"), config.password);
    if (ret) {
        pr_err("Failed to calculate SHA-256 hash\n");
        return ret;
    }

    pr_info("SHA-256 hash of password calculated successfully\n");

    print_hash(config.password);

    rm_off();
    
    if(verify_password("password1", strlen("password1"), config.password)){
    	printk(KERN_INFO "la password corrisponde");
    }
    

    ret = register_kprobe(&kp_vfs_open);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe vfs_open failed, returned %d\n", ret);
        return ret;
    }


    ret = register_kprobe(&kp_vfs_mkdir);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe vfs_mkdir failed, returned %d\n", ret);
        unregister_kprobe(&kp_vfs_open);
        unregister_kprobe(&kp_vfs_unlink);
        return ret;
    }

    ret = register_kprobe(&kp_vfs_rmdir);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe vfs_rmdir failed, returned %d\n", ret);
        unregister_kprobe(&kp_vfs_open);
        unregister_kprobe(&kp_vfs_unlink);
        unregister_kprobe(&kp_vfs_mkdir);
        return ret;
    }

    printk(KERN_INFO "kprobes registered\n");

    printk("%s: reference monitor module correctly loaded\n", MOD_NAME);
    
    // Registra la kprobe
    // Inizializzare deferred workqueue

    return 0;
}

static void my_module_exit(void) {

    unregister_kprobe(&kp_vfs_open);
    unregister_kprobe(&kp_vfs_unlink);
    unregister_kprobe(&kp_vfs_mkdir);
    unregister_kprobe(&kp_vfs_rmdir);

    printk("%s: reference monitor module unloaded\n", MOD_NAME);
    
}

module_init(my_module_init)
module_exit(my_module_exit)
