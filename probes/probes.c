#include <linux/kprobes.h>
#include <linux/slab.h>
#include <asm-generic/errno-base.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/fs_struct.h>

#include "../utils/utils.h"
#include "../utils/constants.h"
#include "../task/tasks.h"
#include "../reference_monitor.h"
#include "probes.h"


struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

struct kretprobe_data {
    int block_flag; // Flag per indicare se l'operazione deve essere bloccata
    path_info info;
};

void mark_inode_read_only(struct inode *inode)
{
        inode->i_mode &= ~S_IWUSR;
        inode->i_mode &= ~S_IWGRP;
        inode->i_mode &= ~S_IWOTH;
        inode->i_flags |= S_IMMUTABLE;
        mark_inode_dirty(inode);
}

void unmark_inode_read_only(struct inode *inode)
{
        inode->i_mode |= S_IWUSR;      // Rendi scrivibile dall'utente
        inode->i_mode |= S_IWGRP;      // Rendi scrivibile dal gruppo
        inode->i_mode |= S_IWOTH;      // Rendi scrivibile da altri
        inode->i_flags &= ~S_IMMUTABLE; // Rimuovi il flag di immutabilità
        mark_inode_dirty(inode);       // Segna l'inode come modificato
}

int mark_inode_read_only_by_pathname(char *pathname, bool mark)
{
        struct path path;
        int ret;
        ret = kern_path(pathname, LOOKUP_FOLLOW, &path);
        if (ret) {
                return ret;
        }

        if (!path.dentry) {
                return -ENOENT;
        }

	if(mark){
	        mark_inode_read_only(path.dentry->d_inode);
        }else{
        	unmark_inode_read_only(path.dentry->d_inode);
        }
        path_put(&path);
        return 0;
}

static int post_handler(struct kretprobe_instance *kp, struct pt_regs *regs){
	struct kretprobe_data *data;
	data = (struct kretprobe_data *)kp->data;

	if (data->block_flag) {
	    schedule_deferred_work();
	    // Imposta il codice di errore per bloccare l'operazione
	    regs->ax = -EACCES;
	    if((data->info).absolute_path!=NULL){
	    	printk(KERN_INFO "%s\n", (data->info).absolute_path);
	    	mark_inode_read_only_by_pathname((data->info).absolute_path, false);
	    }
	    if((data->info).tmp!=NULL) kfree((data->info).tmp);
	    data->block_flag = 0; // Reset del flag
	    printk(KERN_INFO "%s: Operation blocked by kretprobe\n",MOD_NAME);
	}
	
	

	return 0;
}

//			di			si			dx		cx
//int vfs_mkdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode)
static int handler_pre_do_mkdirat(struct kretprobe_instance *kp, struct pt_regs *regs) {
    char *name, *parent;
    
    struct kretprobe_data *data;
    path_info info;
    data  = (struct kretprobe_data *)kp->data;
    
    name = (char *)((struct filename *)(regs->si))->name;

    if (IS_ERR(name)) {
        pr_err(KERN_ERR "%s: Error in get filename\n",MOD_NAME);
        return 0;
    }
    
    if (temp_file(name)) {
        return 0;
    }
    
    info=get_absolute_path(name);
	if (info.absolute_path == NULL) { /*se sto creando un file (quindi abs_path nullo) */
        	// Recupera il percorso della info.absolute_path genitore del file
        	parent = get_dir_parent((char *)name);
        	
        	// Recupera il percorso assoluto della info.absolute_path genitore
        	info = get_absolute_path(parent);

        	// Usa il percorso assoluto della info.absolute_path genitore se è valido
        	if (info.absolute_path == NULL) {
            	// Se il percorso assoluto non è valido, usa la info.absolute_path corrente come fallback
           		info.absolute_path = get_cwd();
        	}
	}

    spin_lock(&RM_lock);
    while (info.absolute_path != NULL && strcmp(info.absolute_path, "") != 0 && strcmp(info.absolute_path, " ") != 0) {

        if (check_list(info.absolute_path)) {

	    data->block_flag=1; //flag per bloccare l'operazione
            data->info=info;
            // Blocca l'operazione modificando il valore dei registri
	    regs->di = (unsigned long)NULL;
	    regs->ax = -EACCES;
	    mark_inode_read_only_by_pathname(info.absolute_path, true);

            printk(KERN_ERR "%s: mkdir operation was blocked: %s\n",MOD_NAME, name);
	    spin_unlock(&RM_lock);
            return 0;
        }

        // Ottieni la info.absolute_path genitore
        info.absolute_path = get_dir_parent(info.absolute_path);
    }
	if(info.tmp!=NULL) kfree(info.tmp);
	spin_unlock(&RM_lock);
    return 0;
}

/* struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};*/
/* struct filename {
	const char		*name;	// pointer to actual string 
	const __user char	*uptr;	// original userland pointer
	int			refcnt;
	struct audit_names	*aname;
	const char		iname[];
};*/
//				di			si			dx
// struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
//uso la do_filp_open perché quando vfs_open utilizzato il file già potrebbe essere stato creato
static int handler_pre_do_filp_open(struct kretprobe_instance *kp, struct pt_regs *regs) {
    int fd;
    struct open_flags *op;
    path_info info;
    const char *path_kernel, *path_user;
    char  *parent;
    int flags;
    
    struct kretprobe_data *data;
    data  = (struct kretprobe_data *)kp->data;
    
    fd=regs->di;
    op=(struct open_flags *)(regs->dx);
    flags=op->open_flag;
    path_kernel = ((struct filename *)(regs->si))->name;
    path_user = ((struct filename *)(regs->si))->uptr;
    
    if(strncmp(path_kernel, "/run", 4) == 0) {
        return 0;
    }
    
    info=get_absolute_path(path_kernel);

    // Logica per decidere se bloccare l'operazione
    
    //se il file è aperto in lettura, ritorno 	
	if(!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL ))){
		//if(info.tmp!=NULL) kfree(info.tmp);
		return 0;
	}
	
	if(flags & O_CREAT){
		if (info.absolute_path == NULL) { /*se sto creando un file (quindi abs_path nullo) */
		    	// Recupera il percorso della info.absolute_path genitore del file
		    	parent = get_dir_parent((char *)path_kernel);
			
		    	// Recupera il percorso assoluto della info.absolute_path genitore
		    	info = get_absolute_path(parent);

		    	// Usa il percorso assoluto della info.absolute_path genitore se è valido
		    	if (info.absolute_path == NULL) {
		        	// Se il percorso assoluto non è valido, usa la info.absolute_path corrente come fallback
		       		info.absolute_path = get_cwd();
		    	}
		}
	}
	
	spin_lock(&RM_lock);
	
	while (info.absolute_path!=NULL && strcmp(info.absolute_path, "") != 0 && strcmp(info.absolute_path, " ") != 0){ //controllo che sia non NULL e non vuoto.
	
		if(check_list(info.absolute_path)){
			data->block_flag=1;
			printk(KERN_ERR "%s: Bloccata scrittura su file vietato %s.\n", MOD_NAME, info.absolute_path);
			op->open_flag = O_RDONLY;
			if(info.tmp!=NULL) kfree(info.tmp);
			spin_unlock(&RM_lock);
           		return 0;
		}
		
		info.absolute_path = get_dir_parent(info.absolute_path); //itero sui parent della info.absolute_path passata
	}
	
	if(info.tmp!=NULL) kfree(info.tmp);
	spin_unlock(&RM_lock);
        return 0;
}

// si: struct inode*
// dx: struct dentry *
static int handler_pre_rm(struct kretprobe_instance *kp, struct pt_regs *regs) {
    struct dentry *dentry;
    char *name;
    path_info info;
    struct kretprobe_data *data;

	data  = (struct kretprobe_data *)kp->data;
	dentry = (struct dentry *)regs->dx;

	name = (char *)((struct filename *)(regs->si))->name;

    if (IS_ERR(name)) {
        pr_err(KERN_ERR "%s:Errore nell'ottenere il nome del file\n", MOD_NAME);
        return 1;
    }
    
	//se temp-file nop
	if(temp_file(name)){	
		return 0;
	}
	
	//percorso assoluto
	info=get_absolute_path(name);
	if(info.absolute_path==NULL) return 1;
	//controlla se path presente nella lista dei file bloccati
	spin_lock(&RM_lock);
    while (info.absolute_path != NULL && strcmp(info.absolute_path, "") != 0 && strcmp(info.absolute_path, " ") != 0) {

        if (check_list(info.absolute_path)) {

	    data->block_flag=1; //flag per bloccare l'operazione
	    data->info=info;
            
            // Blocca l'operazione modificando il valore dei registri
	    regs->di = (unsigned long)NULL;
	    mark_inode_read_only_by_pathname(info.absolute_path, true);
	    regs->ax = -EACCES;

            printk(KERN_ERR "%s: rmdir/unlinkat operation was blocked: %s\n",MOD_NAME, name);
	    spin_unlock(&RM_lock);
            return 0;
        }

        // Ottieni la info.absolute_path genitore
        info.absolute_path = get_dir_parent(info.absolute_path);
    }
	if(info.tmp!=NULL) kfree(info.tmp);
	spin_unlock(&RM_lock);
    return 0;
}

static struct kretprobe kp_do_filp_open = {
    .kp.symbol_name=DO_FILP_OPEN,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler= handler_pre_do_filp_open,
    .handler=post_handler
};

static struct kretprobe kp_do_rmdir = {
    .kp.symbol_name=DO_RMDIR,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler=handler_pre_rm,
    .handler=post_handler
};

static struct kretprobe kp_do_mkdir = {
    .kp.symbol_name=DO_MKDIRAT,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler= handler_pre_do_mkdirat,
    .handler=post_handler
};

static struct kretprobe kp_do_unlinkat = {
    .kp.symbol_name = DO_UNLINKAT,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler=handler_pre_rm,
    .handler=post_handler
};

int register_probes(){
	int ret=0;
	
	ret = register_kretprobe(&kp_do_filp_open);
    if (ret < 0) {
        printk(KERN_INFO "%s: register_kprobe do_filp_open failed, returned %d\n", MOD_NAME,ret);
        return ret;
    }

	ret = register_kretprobe(&kp_do_unlinkat);
    if (ret < 0) {
        printk(KERN_INFO "%s: register_kprobe vfs_unlink failed, returned %d\n", MOD_NAME,ret);
        unregister_kretprobe(&kp_do_filp_open);
        return ret;
    }

    ret = register_kretprobe(&kp_do_mkdir);
    if (ret < 0) {
        printk(KERN_INFO "%s: register_kprobe vfs_mkdir failed, returned %d\n", MOD_NAME,ret);
        unregister_kretprobe(&kp_do_filp_open);
        unregister_kretprobe(&kp_do_unlinkat);
        return ret;
    }

    ret = register_kretprobe(&kp_do_rmdir);
    if (ret < 0) {
        printk(KERN_INFO "%s: register_kprobe vfs_rmdir failed, returned %d\n", MOD_NAME,ret);
        unregister_kretprobe(&kp_do_filp_open);
        unregister_kretprobe(&kp_do_unlinkat);
        unregister_kretprobe(&kp_do_mkdir);
        return ret;
    }
    
    printk(KERN_INFO "%s: kprobes registered\n", MOD_NAME);
    
    return 0;
	
}

void unregister_probes(){
    unregister_kretprobe(&kp_do_filp_open);
    unregister_kretprobe(&kp_do_unlinkat);
    unregister_kretprobe(&kp_do_mkdir);
    unregister_kretprobe(&kp_do_rmdir);
    
    printk(KERN_INFO "%s: kprobes unregistered\n", MOD_NAME);
    
}

void enable_probes(){
	enable_kretprobe(&kp_do_filp_open);
	enable_kretprobe(&kp_do_unlinkat);
	enable_kretprobe(&kp_do_mkdir);
	enable_kretprobe(&kp_do_rmdir);
    
    printk(KERN_INFO "%s: kprobes enabled\n", MOD_NAME);
}

void disable_probes(){
    disable_kretprobe(&kp_do_filp_open);
    disable_kretprobe(&kp_do_unlinkat);
    disable_kretprobe(&kp_do_mkdir);
    disable_kretprobe(&kp_do_rmdir);
    
    printk(KERN_INFO "%s: kprobes disabled\n", MOD_NAME);
}
