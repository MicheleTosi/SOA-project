#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uio.h>	// per struct iov_iter

#include "singlefilefs.h"

static struct mutex lock_log;

ssize_t onefilefs_write_iter(struct kiocb *iocb, struct iov_iter *from){
	
	struct buffer_head *bh = NULL;
	struct file *filp=iocb->ki_filp; 		// ptr alla struttura file da kiocb
	struct inode *the_inode=filp->f_inode;	// inode del file
	
	char *buf_data = from->kvec->iov_base;	// buffer dati da scrivere
	size_t len = from->kvec->iov_len;		// lunghezza buffer
	
	int block_to_write;						// indice del blocco da scrivere sul dispositivo
	loff_t offset;							// offset nel blocco corrente
	loff_t append_offset;					// offset da cui iniziare la scrittura
	
	mutex_lock(&lock_log);
	
	append_offset= i_size_read(the_inode);	// offset da cui deve iniziare la scrittura
	
	offset = append_offset % DEFAULT_BLOCK_SIZE;
	
	if (offset + len > DEFAULT_BLOCK_SIZE)	// lavoro su singolo blocco, il resto viene gestito ad application level
		len = DEFAULT_BLOCK_SIZE - offset;
	
	//indice del blocco che deve essere scritto
	block_to_write = append_offset / DEFAULT_BLOCK_SIZE + 2;	// +2 per superblock e inode block
	
	// carico il blocco specifico nel buffer
	bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_write);
    if(!bh){
    	mutex_unlock(&lock_log);
		return -EIO;
    }
    
    memcpy(bh->b_data + offset, buf_data, len);	// scrittura vera e propria
    
    mark_buffer_dirty(bh);						// segnalazione blocco deve essere scritto sul disco
    sync_dirty_buffer(bh);						// sincronizzazione sul disco
    
    append_offset += len;						// nuova posizione da cui scrivere
    
 	the_inode->i_size = append_offset;			        // nuovo offset
 	i_size_write(the_inode, append_offset);			// aggiornamento dimensione
 	brelse(bh);							// rilascio buffer
 	mutex_unlock(&lock_log);
 	
 	return len;
	
	
}

ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    loff_t offset;
    int block_to_read;//index of the block to be read from device

    printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)",MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason
	mutex_lock(&lock_log);
	//down_write(&the_inode->i_rwsem);

    //check that *off is within boundaries
    if (*off >= file_size){
    	mutex_unlock(&lock_log);
        //up_write(&the_inode->i_rwsem);
        return 0;
    }
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
	    mutex_unlock(&lock_log);
		//up_write(&the_inode->i_rwsem);
		return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);
	mutex_unlock(&lock_log);
	//up_write(&the_inode->i_rwsem);

    return len - ret;

}


struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

	
		//get a locked inode from the cache 
		the_inode = iget_locked(sb, 1);
		if (!the_inode)
			return ERR_PTR(-ENOMEM);

		//already cached inode - simply return successfully
		if(!(the_inode->i_state & I_NEW)){
			return child_dentry;
		}


		//this work is done if the inode was not already cached
		inode_init_owner(current->cred->user_ns, the_inode, NULL, S_IFREG );
		the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
		the_inode->i_fop = &onefilefs_file_operations;
		the_inode->i_op = &onefilefs_inode_ops;

		//just one link for this file
		set_nlink(the_inode,1);

		//now we retrieve the file size via the FS specific inode, putting it into the generic inode
		bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
	   	if(!bh){
			iput(the_inode);
			return ERR_PTR(-EIO);
	   	}
		FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
		the_inode->i_size = FS_specific_inode->file_size;
		brelse(bh);

		d_add(child_dentry, the_inode);
		dget(child_dentry);

		//unlock the inode to make it usable 
		unlock_new_inode(the_inode);

		return child_dentry;
    }

    return NULL;

}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_write_iter
};
