/* vramfs.c
 *
 * main source file for pseudo-filesystem allowing video RAM
 * to be mapped and allocated as a filesystem (tmpfs for vram)
 * (C) 2008 Impact Studio Pro. Written by Jonathan Campbell.
 */

#include <linux/capability.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/parser.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mman.h>
#include <linux/pci.h>
#include <linux/vfs.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <asm/io.h>

#include "vramfs.h"

/* "comparison of pointers lacks defined data type"?
 * what the fuck are you talking about GCC? */
#define min_int(a,b) (a < b ? a : b)

#if defined(VRAMFS_DEBUG)
# define DBG_(x,...) printk(KERN_INFO "vramfs: " x "\n", __VA_ARGS__ )
# define DBG(x) printk(KERN_INFO "vramfs: " x "\n")
#else
# define DBG_(x,...) { }
# define DBG(x) { }
#endif

#define SB_P(x) ( (struct vramfs_sb_priv*)((x)->s_fs_info) )

#define INODE_BASE 1
#define INODE_ROOT 1

#define VRAMFS_MAGIC 0x12345678

static int enable_fake_vram = 0;
module_param(enable_fake_vram,int,0);
MODULE_PARM_DESC(enable_fake_vram,"If no device or memory range given, emulate VRAM using physical memory (for debugging purposes)");

static int default_mmap = 1;
module_param(default_mmap,int,0);
MODULE_PARM_DESC(default_mmap,"Default mmap= setting. Default is 1 (on)");

static const int default_inode_max = 512;

static const int fake_blocks = 40;
static int fake_vram_order = 0;
static unsigned long fake_vram = 0;
static unsigned long fake_vramv = 0;
static void* fake_vram_buffer = NULL;

static int init_fake_vram(void) {
	if (!fake_vram) {
		unsigned long size = fake_blocks * PAGE_SIZE;
		int order = 1;

		while ((size >> order) > PAGE_SIZE)
			order++;

		DBG_("fake vram: blocks=%d => page size order=%d",
			fake_blocks,order);

		fake_vramv = __get_free_pages(0,order);
		if (!fake_vramv) return 1;
		fake_vram_buffer = (void*)fake_vramv;
		fake_vram_order = order;

		fake_vram = virt_to_phys((void*)fake_vramv);

		DBG_("fake vram is at 0x%08lX-0x%08lx (virtual)",fake_vramv,
			fake_vramv+size-1);
		DBG_("fake vram is at 0x%08lX-0x%08lx (physical)",fake_vram,
			fake_vram+size-1);
	}

	return 0;
}

static void free_fake_vram(void) {
	if (fake_vramv) {
		free_pages(fake_vramv,fake_vram_order);
		fake_vram_buffer = NULL;
		fake_vramv = 0;
		fake_vram = 0;
	}
}

struct vramfs_inode {
/* point back to superblock */
	struct super_block*	vi_sb;	/* NULL if not allocated */
/* for the vfs */
	struct timespec		atime,ctime,mtime;
	char*			symlink;
	unsigned int		parent;
	char*			name;
	int			mode;
	ssize_t			size;
	int			uid;
	int			gid;

	int			first_block;
};

struct vramfs_sb_priv {
	/* inodes. numbered 1 <= x <= inode_max (0 is not a valid inode) */
	int			inode_max;
	struct vramfs_inode*	inode_list;

	int			allow_mmap;

	int			blocks;	/* number of blocks */
	uint8_t*		bmap_reserved; /* root can mark blocks reserved */
	unsigned long*		bmap; /* mapping of block->inode */

	unsigned long		vram_base;
	unsigned long		vram_fence;

	spinlock_t		lock;
};

static unsigned long vramfs_sb_lock(struct vramfs_sb_priv *p) {
	unsigned long flags;
	spin_lock_irqsave(&p->lock,flags);
	return flags;
}

static void vramfs_sb_unlock(struct vramfs_sb_priv *p,unsigned long f) {
	spin_unlock_irqrestore(&p->lock,f);
}

static void free_vram_inode(struct vramfs_inode *i);
static struct inode *vramfs_create_inode(struct inode *parent_inode,int mode,const char *name);
static struct vramfs_inode *get_vram_inode_entry(struct vramfs_sb_priv *p,int x);

static int fill_super(struct super_block *sb, void *data, int flags);

static int get_sb(struct file_system_type *fst,
	int flags, const char *devname, void *data, struct vfsmount *vfs) {
	return get_sb_nodev(fst, flags, data, fill_super, vfs);
}

static void dirty_inode(struct inode *i) {
	DBG("dirty inode");
}

static int write_inode(struct inode *i,int n) {
	DBG("write_inode");
	return -ENOSYS;
}

static void delete_inode(struct inode *inode) {
	unsigned long spl =
		vramfs_sb_lock(SB_P(inode->i_sb));

	if (!inode->i_nlink) {
		int blk;
		struct vramfs_inode *vi =
			get_vram_inode_entry(SB_P(inode->i_sb),inode->i_ino);
		struct vramfs_sb_priv *sbp = SB_P(inode->i_sb);
		DBG("nlink == 0, dropping inode entirely");
		if (vi != NULL) free_vram_inode(vi);

		for (blk=0;blk < sbp->blocks;blk++)
			if (sbp->bmap[blk] == inode->i_ino)
				sbp->bmap[blk] = 0;
	}

	vramfs_sb_unlock(SB_P(inode->i_sb),spl);
	clear_inode(inode);
}

static int init_sb_priv(struct vramfs_sb_priv *p,int blocks,uint64_t base) {
	if (blocks < 4)
		return -1;

	p->blocks = blocks;

	p->inode_max = default_inode_max;
	p->inode_list = kzalloc(
		sizeof(struct vramfs_inode) * p->inode_max,
		GFP_KERNEL);
	if (!p->inode_list) {
		return -1;
	}

	p->bmap = kzalloc(sizeof(unsigned long) * p->blocks,GFP_KERNEL);
	if (!p->bmap) {
		kfree(p->inode_list);
		return -1;
	}

	p->bmap_reserved = kzalloc(sizeof(uint8_t) * p->blocks,GFP_KERNEL);
	if (!p->bmap_reserved) {
		kfree(p->inode_list);
		kfree(p->bmap);
		return -1;
	}

	p->vram_base = base;
	p->vram_fence = base + (blocks * PAGE_SIZE);
	DBG_("init sb: vram 0x%08lX-0x%08lX",
		(unsigned long int)p->vram_base,
		(unsigned long int)p->vram_fence-1);

	p->lock = SPIN_LOCK_UNLOCKED;
	return 0;
}

static struct vramfs_inode *get_vram_inode_entry(struct vramfs_sb_priv *p,int x) {
	if (x < INODE_BASE || x >= p->inode_max+INODE_BASE) return NULL;
	return p->inode_list + x - INODE_BASE;
}

struct inode *vramfs_iget(struct super_block *sb,unsigned long ino);

/* call this with the spinlock held */
static void free_vram_inode(struct vramfs_inode *i) {
	if (i->name) {
		kfree(i->name);
		i->name = NULL;
	}
	if (i->symlink) {
		kfree(i->symlink);
		i->symlink = NULL;
	}
	i->parent = 0;
	i->vi_sb = NULL;
}

static void free_sb_priv(struct vramfs_sb_priv *p) {
	if (p->inode_list) {
		int i;

		for (i=0;i < p->inode_max;i++)
			free_vram_inode(p->inode_list+i);

		kfree(p->inode_list);
		p->inode_list = NULL;
	}
	if (p->bmap_reserved) {
		kfree(p->bmap_reserved);
		p->bmap_reserved = NULL;
	}
	if (p->bmap) {
		kfree(p->bmap);
		p->bmap = NULL;
	}
}

static void put_super(struct super_block *s) {
	if (s->s_fs_info) {
		free_sb_priv((struct vramfs_sb_priv*)(s->s_fs_info));
		kfree(s->s_fs_info);
		s->s_fs_info = NULL;
	}
}

static void write_super(struct super_block *s) {
}

static int vramfs_inodes_active(struct vramfs_sb_priv *p) {
	int i=0,c=0;

	/* we don't care if race conditions cause minor errors,
	 * no spinlock here. */
	while (i < p->inode_max) {
		struct vramfs_inode *inode =
			p->inode_list + (i++);

		c += (inode->vi_sb != NULL);
	}

	return c;
}

static int vramfs_blocks_taken(struct vramfs_sb_priv *p) {
	int i=0,c=0;

	/* we don't care if race conditions cause minor errors,
	 * no spinlock here. */
	while (i < p->blocks)
		c += (p->bmap[i++] != 0);

	return c;
}

static int statfs(struct dentry *d,struct kstatfs *kst) {
	struct super_block *sb = d->d_sb;
	struct vramfs_sb_priv *p = (struct vramfs_sb_priv*)(sb->s_fs_info);

	kst->f_type = VRAMFS_MAGIC;
	kst->f_bsize = PAGE_SIZE;
	kst->f_blocks = p->blocks;
	kst->f_bfree = kst->f_bavail = p->blocks - vramfs_blocks_taken(p);
	kst->f_files = vramfs_inodes_active(p);
	kst->f_ffree = p->inode_max - kst->f_files;
	kst->f_namelen = 256;
	return 0;
}

static int remount_fs(struct super_block *s,int *i,char *data) {
	DBG("remount_fs");
	return -ENOSYS;
}

static void do_clear_inode(struct inode *i) {
	DBG_("clear_inode %u",(unsigned int)(i->i_ino));
}

static void umount_begin(struct super_block *s) {
	DBG("umount_begin");
}

static int show_options(struct seq_file *seq,struct vfsmount *mnt) {
	return 0;
}

static struct super_operations vramfs_sops = {
	.dirty_inode =		dirty_inode,
	.write_inode =		write_inode,
	.delete_inode =		delete_inode,
	.put_super =		put_super,
	.write_super =		write_super,
	.statfs =		statfs,
	.remount_fs =		remount_fs,
	.clear_inode =		do_clear_inode,
	.umount_begin =		umount_begin,
	.show_options =		show_options,
};

static struct file_system_type fst_vramfs = {
	.name =			"vramfs",
	.fs_flags =		0,
	.owner =		THIS_MODULE,
	.get_sb =		get_sb,
	.kill_sb =		kill_anon_super
};

static int vramfs_create(struct inode *i,struct dentry *d,int mode,struct nameidata *n) {
	unsigned long spl = vramfs_sb_lock(SB_P(i->i_sb));
	struct inode *inode = vramfs_create_inode(i,mode | S_IFREG,d->d_name.name);
	vramfs_sb_unlock(SB_P(i->i_sb),spl);
	DBG_("create in %u, '%s' mode %o",
	    (unsigned int)i->i_ino,d->d_name.name,mode);
	if (IS_ERR(inode)) return (size_t)inode;
	d_instantiate(d,inode);
	return 0;
}

static int vramfs_mkdir(struct inode *i,struct dentry *d,int mode) {
	unsigned long spl = vramfs_sb_lock(SB_P(i->i_sb));
	struct inode *inode = vramfs_create_inode(i,mode | S_IFDIR,d->d_name.name);
	vramfs_sb_unlock(SB_P(i->i_sb),spl);
	DBG_("mkdir in %u, '%s' mode %o",
	    (unsigned int)i->i_ino,d->d_name.name,mode);
	if (IS_ERR(inode)) return (size_t)inode;
	d_instantiate(d,inode);
	return 0;
}

static int vramfs_symlink(struct inode *i,struct dentry *d,const char *where) {
	unsigned long spl = vramfs_sb_lock(SB_P(i->i_sb));
	struct inode *inode = vramfs_create_inode(i,S_IFLNK | 0777,d->d_name.name);
	if (!IS_ERR(inode)) { /* <- aka "no error" */
		int wherel = strlen(where);
		struct vramfs_inode *vi =
			get_vram_inode_entry(SB_P(i->i_sb),inode->i_ino);
		if (vi) {
			vi->symlink = kmalloc(wherel+1,GFP_KERNEL);
			if (vi->symlink)
				memcpy(vi->symlink,where,wherel+1);
		}
	}
	vramfs_sb_unlock(SB_P(i->i_sb),spl);
	DBG_("symlink in %u, '%s' -> '%s'",
	    (unsigned int)i->i_ino,d->d_name.name,where);
	if (IS_ERR(inode)) return (size_t)inode;
	d_instantiate(d,inode);
	return 0;
}

static int vramfs_unlink(struct inode *dir,struct dentry *d) {
	struct inode *inode = d->d_inode;
	DBG_("unlink %u in %u",
		(unsigned int)inode->i_ino,
		(unsigned int)dir->i_ino);
	drop_nlink(inode);
	return 0;
}

static int vramfs_rmdir(struct inode *dir,struct dentry *d) {
	unsigned long spl;
	struct inode *inode = d->d_inode;
	struct super_block *sb = dir->i_sb;
	struct vramfs_sb_priv *sbp = SB_P(sb);
	int ino;

	DBG_("rmdir %u in %u",
		(unsigned int)inode->i_ino,
		(unsigned int)dir->i_ino);

	if ((dir->i_mode & S_IFMT) != S_IFDIR)
		return -ENOTDIR;

	/* if anything is still a "child" of this then fail */
	spl = vramfs_sb_lock(sbp);
	for (ino=INODE_BASE;ino < (sbp->inode_max+INODE_BASE);ino++) {
		struct vramfs_inode *vi =
			get_vram_inode_entry(sbp,ino);

		if (vi == NULL || vi->vi_sb == NULL || vi->name == NULL)
			continue;
		if (vi->parent == inode->i_ino)
			return -ENOTEMPTY;
	}

	if (inode->i_nlink != 2)
		DBG("   nlink != 2?");

	drop_nlink(inode);
	drop_nlink(inode);

	vramfs_sb_unlock(sbp,spl);
	return 0;
}

static int vramfs_permission(struct inode *inode,int mask) {
	return generic_permission(inode,mask,NULL);
}

static int vramfs_getattr(struct vfsmount *vfs,struct dentry *d,struct kstat *stat) {
/*	struct super_block *sb = vfs->mnt_sb; */
/*	struct vramfs_sb_priv *sbp = SB_P(sb); */
	struct inode *inode = d->d_inode;
	generic_fillattr(inode,stat);
	stat->blksize = PAGE_SIZE;
	return 0;
}

static struct dentry *vramfs_lookup(struct inode *dir,struct dentry *dentry,struct nameidata *nd) {
	struct super_block *sb = dir->i_sb;
	struct vramfs_sb_priv *sbp = SB_P(sb);
	struct inode *inode = NULL;
	struct vramfs_inode *vi;
	int ino;

	for (ino=INODE_BASE;ino < sbp->inode_max+INODE_BASE && inode == NULL;ino++) {
		if ((vi = get_vram_inode_entry(sbp,ino)) == NULL)
			continue;
		if (vi->vi_sb == NULL || vi->name == NULL ||
			vi->parent != dir->i_ino)
			continue;

		if (!strcmp(vi->name,dentry->d_name.name))
			inode = vramfs_iget(sb,ino);
	}

	d_add(dentry,inode);
	return NULL;
}

static int vramfs_readlink(struct dentry *d,char __user *buf,int len) {
	struct inode *inode = d->d_inode;
	struct super_block *sb = inode->i_sb;
	struct vramfs_sb_priv *sbp = SB_P(sb);
	struct vramfs_inode *vi =
		get_vram_inode_entry(sbp,inode->i_ino);
	int sll,err;

	DBG_("readlink inode %u",(unsigned int)(inode->i_ino));

	if (vi == NULL || vi->vi_sb == NULL)
		return -ENOENT;

	if (vi->symlink == NULL || (vi->mode & S_IFMT) != S_IFLNK)
		return -EINVAL;

	sll = strlen(vi->symlink);
	if (sll > len) sll = len;

	if (sll > 0)
		if ((err=copy_to_user(buf,vi->symlink,sll)) < 0)
			return err;

	return sll;
}

static void *vramfs_follow_link(struct dentry *d,struct nameidata *nd) {
	struct vramfs_inode *vi =
		get_vram_inode_entry(SB_P(d->d_inode->i_sb),
			d->d_inode->i_ino);
	DBG_("follow_link(inode %u)",(unsigned int)d->d_inode->i_ino);
	nd_set_link(nd, vi->symlink);
	return NULL;
}

static void vramfs_truncate(struct inode *inode) {
	struct super_block *sb = inode->i_sb;
	struct vramfs_sb_priv *sbp = SB_P(sb);
	struct vramfs_inode *vi = get_vram_inode_entry(sbp,inode->i_ino);
	int nblks = (inode->i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long spl;
	int blk;

	spl = vramfs_sb_lock(SB_P(inode->i_sb));

	DBG_("truncate %u to %Lu",
		(unsigned int)inode->i_ino,
		inode->i_size);

	vi->size = inode->i_size;

	for (blk=0;blk < nblks && blk+vi->first_block < sbp->blocks;blk++) {
		int bn = blk+vi->first_block;
		if (sbp->bmap[bn] != inode->i_ino ||
			(sbp->bmap_reserved[bn] && sbp->bmap[bn] == 0)) {
			vi->size = inode->i_size = blk * PAGE_SIZE;
			break;
		}
		else if (sbp->bmap[bn] == 0)
			sbp->bmap[bn] = inode->i_ino;
	}
	for (;blk+vi->first_block < sbp->blocks;blk++)
		if (sbp->bmap[blk+vi->first_block] == inode->i_ino)
			sbp->bmap[blk+vi->first_block] = 0;

	vramfs_sb_unlock(SB_P(inode->i_sb),spl);
}

static struct inode_operations vramfs_dir_iops = {
	.getattr =		vramfs_getattr,
	.create =		vramfs_create,
	.mkdir =		vramfs_mkdir,
	.unlink =		vramfs_unlink,
	.symlink =		vramfs_symlink,
	.readlink =		vramfs_readlink,
	.rmdir =		vramfs_rmdir,
	.lookup =		vramfs_lookup,
	.permission =		vramfs_permission,
	.truncate =		vramfs_truncate,
};

static struct inode_operations vramfs_file_iops = {
	.getattr =		vramfs_getattr,
	.mkdir =		vramfs_mkdir,
	.unlink =		vramfs_unlink,
	.permission =		vramfs_permission,
	.truncate =		vramfs_truncate,
};

static struct inode_operations vramfs_symlink_iops = {
	.getattr =		vramfs_getattr,
	.readlink =		vramfs_readlink,
	.follow_link =		vramfs_follow_link,
	.put_link =		page_put_link,
	.permission =		vramfs_permission,
	.truncate =		vramfs_truncate,
};

static int vramfs_readdir(struct file *filp,void *dirent,filldir_t filldir) {
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct vramfs_sb_priv *sbp = SB_P(sb);

	DBG("readdir");

	while (filp->f_pos < 2+sbp->inode_max) {
		if (filp->f_pos == 0) {
			if (filldir(dirent, ".", 1, 0, inode->i_ino, DT_DIR))
				break;
			filp->f_pos++;
		}
		else if (filp->f_pos == 1) {
			if (filldir(dirent, "..", 2, 1, inode->i_ino, DT_DIR))
				break;
			filp->f_pos++;
		}
		else {
			struct vramfs_inode *vi =
				get_vram_inode_entry(sbp,filp->f_pos+INODE_BASE-2);
			if (vi == NULL || vi->vi_sb == NULL) {
				filp->f_pos++;
				continue;
			}

			if (vi->parent != inode->i_ino) {
				filp->f_pos++;
				continue;
			}

			if (filldir(dirent, vi->name, strlen(vi->name),
				filp->f_pos, filp->f_pos+INODE_BASE-2,
				(vi->mode >> 12) & 15))
				break;

			filp->f_pos++;
		}
	}

	return 0;
}

struct vramfs_file {
	struct inode *f_ino;
};

static int vramfs_open(struct inode *i,struct file *f) {
	struct vramfs_file *pf = kzalloc(
		sizeof(struct vramfs_file),GFP_KERNEL);

	if (!pf) return -ENOMEM;
	pf->f_ino = i;
	f->private_data = pf;

	DBG_("open inode %u",(unsigned int)i->i_ino);

	return 0;
}

static int vramfs_release(struct inode *i,struct file *f) {
	struct vramfs_file *pf = f->private_data;
	DBG_("release %u",(unsigned int)i->i_ino);
	if (pf) {
		if (pf->f_ino != i)
			DBG("WARNING: open() inode differs from release inode");

		kfree(pf);
		f->private_data = NULL;
	}
	return 0;
}

/* HACK: don't hold spinlock inside read/write? */
#define vramfs_sb_lock(x) 0
#define vramfs_sb_unlock(x,y)

static ssize_t vramfs_read(struct file *f,char __user *buf,size_t len,loff_t *of) {
	struct vramfs_file *pf = f->private_data;
	struct vramfs_sb_priv *sbp;
	struct vramfs_inode *vi;
	struct super_block *sb;
	struct inode *inode;
	unsigned long spl;
	int ret = 0;

	DBG("read::pf");
	if (pf == NULL) {
		return -EINVAL;
	}

	DBG("read::inode");
	inode = pf->f_ino;
	if (inode == NULL) {
		return -EINVAL;
	}

	DBG_("read::inode %u",(unsigned int)(inode->i_ino));
	if ((inode->i_mode & S_IFMT) != S_IFREG) {
		return -EINVAL;
	}

	spl = vramfs_sb_lock(SB_P(inode->i_sb));

	sb = inode->i_sb;
	sbp = SB_P(sb);
	vi = get_vram_inode_entry(sbp,inode->i_ino);
	DBG("read::vi");
	if (vi == NULL || vi->vi_sb == NULL) {
		vramfs_sb_unlock(SB_P(inode->i_sb),spl);
		return -EINVAL;
	}

	if (f->f_pos >= vi->size) {
		vramfs_sb_unlock(SB_P(inode->i_sb),spl);
		return 0;
	}

	if (vi->first_block < 0) {
		vramfs_sb_unlock(SB_P(inode->i_sb),spl);
		return 0;
	}

	DBG_("read @ %Lu",(unsigned long long)(f->f_pos));

	while (len > 0) {
		ssize_t frem = vi->size - f->f_pos;
		int bofs = f->f_pos & (PAGE_SIZE - 1);
		int brem = PAGE_SIZE - bofs;
		int tor = min_int(min_int(brem,len),frem);
		int block = vi->first_block +
			(f->f_pos >> PAGE_SHIFT);
		unsigned char *ipage;
		unsigned long addr;

		if (tor <= 0)
			break;

		DBG_("read block %u @ %u len %u",
			block,bofs,tor);

		addr = sbp->vram_base + block*PAGE_SIZE;
		DBG_("ioremap(0x%08lX)",(unsigned long int)addr);
		ipage = ioremap(addr,PAGE_SIZE);
		if (!ipage) {
			vramfs_sb_unlock(SB_P(inode->i_sb),spl);
			return -EIO;
		}

		if (copy_to_user(buf,ipage+bofs,tor)) {
			vramfs_sb_unlock(SB_P(inode->i_sb),spl);
			iounmap(ipage);
			return -EIO;
		}

		iounmap(ipage);
		f->f_pos += tor;
		if (of) *of = f->f_pos;
		len -= tor;
		buf += tor;
		ret += tor;
	}

	vramfs_sb_unlock(SB_P(inode->i_sb),spl);
	return ret;
}

static int vramfs_find_free_block(struct vramfs_sb_priv *sbp) {
	int blk;

	for (blk=0;blk < sbp->blocks;blk++)
		if (sbp->bmap[blk] == 0 && sbp->bmap_reserved[blk] == 0)
			return blk;

	return -1;
}

static ssize_t vramfs_write(struct file *f,const char __user *buf,size_t len,loff_t *of) {
	struct vramfs_file *pf = f->private_data;
	struct vramfs_sb_priv *sbp;
	struct vramfs_inode *vi;
	struct super_block *sb;
	struct inode *inode;
	int patience = 100;
	unsigned long spl;
	int ret = 0;

	DBG("write::pf");
	if (pf == NULL) return -EINVAL;

	inode = pf->f_ino;
	DBG("write::inode");
	if (inode == NULL) return -EINVAL;

	DBG_("write::inode #%u %o",(unsigned int)(inode->i_ino),inode->i_mode);
	if ((inode->i_mode & S_IFMT) != S_IFREG) return -EINVAL;

	spl = vramfs_sb_lock(SB_P(inode->i_sb));

	sb = inode->i_sb;
	sbp = SB_P(sb);
	vi = get_vram_inode_entry(sbp,inode->i_ino);

	DBG("write::vi");
	if (vi == NULL || vi->vi_sb == NULL) {
		vramfs_sb_unlock(SB_P(inode->i_sb),spl);
		return -EINVAL;
	}

	DBG_("write @ %Lu",(unsigned long long)(f->f_pos));

	if (vi->first_block < 0) {
		/* nothing allocated to the inode, so find
		 * the first free block and give it to the
		 * inode */
		int block = vramfs_find_free_block(sbp);
		if (block < 0) {
			vramfs_sb_unlock(SB_P(inode->i_sb),spl);
			return -ENOSPC;
		}
		vi->first_block = block;
		sbp->bmap[block] = inode->i_ino;

		DBG_("write inode %u, giving it it's first block %u",
			(unsigned int)(inode->i_ino),block);
	}

	while (len > 0 && patience-- > 0) {
		ssize_t frem = vi->size - f->f_pos;
		int bofs = f->f_pos & (PAGE_SIZE - 1);
		int brem = PAGE_SIZE - bofs;
		int tor = min_int(min_int(brem,len),frem);
		int block = vi->first_block +
			(f->f_pos >> PAGE_SHIFT);
		unsigned long addr = sbp->vram_base + block*PAGE_SIZE;
		unsigned char *ipage;

		if (tor <= 0) {
			int ntor = min_int(brem,len);

			/* try to expand the file.
			 * or at least continue the write by filling out
			 * the current block. or, give up if this inode's
			 * landlocked (blocked by the next block occupied
			 * by another inode). remember, in this fs files
			 * can only be contigious, never fragmented. */
			DBG_("write inode %u, out of allocated range (%Lu/%Lu)",
				(unsigned int)(inode->i_ino),
				(unsigned long long)f->f_pos,
				(unsigned long long)vi->size);

			if (bofs != 0) {
				/* fill out the block before we try to allocate more. */
				inode->i_size = (vi->size += ntor);
				DBG_("filling out block @ ofs %u with %u",
					bofs,ntor);
				continue;
			}

			/* "block" then refers to the block following the inode's range.
			 * see if the next block is available, and if so, take it.
			 * but don't overrun the valid range! */
			if (block >= sbp->blocks) {
				DBG("nope. cannot alloc blocks past end of block range");
				if (ret == 0) {
					vramfs_sb_unlock(SB_P(inode->i_sb),spl);
					return -ENOSPC;
				}
				else break;
			}
			if (sbp->bmap[block] != 0 && sbp->bmap[block] != inode->i_ino) {
				DBG("nope. next block is owned by another inode");
				if (ret == 0) {
					vramfs_sb_unlock(SB_P(inode->i_sb),spl);
					return -ENOSPC;
				}
				else break;
			}
			if (sbp->bmap_reserved[block] && sbp->bmap[block] != inode->i_ino) {
				DBG("nope. next block is reserved");
				if (ret == 0) {
					vramfs_sb_unlock(SB_P(inode->i_sb),spl);
					return -ENOSPC;
				}
				else break;
			}

			/* take it! */
			DBG_("taking block %u to continue taking data (%u bytes)",(unsigned int)block,ntor);
			sbp->bmap[block] = inode->i_ino;
			inode->i_size = (vi->size += ntor);
			continue;
		}
	
		DBG_("ioremap(0x%08lX)",(unsigned long int)addr);
		ipage = ioremap(addr,PAGE_SIZE);
		if (!ipage) {
			vramfs_sb_unlock(SB_P(inode->i_sb),spl);
			return -EIO;
		}

		if (copy_from_user(ipage+bofs,buf,tor)) {
			vramfs_sb_unlock(SB_P(inode->i_sb),spl);
			iounmap(ipage);
			return -EIO;
		}

		iounmap(ipage);
		f->f_pos += tor;
		if (of) *of = f->f_pos;
		len -= tor;
		buf += tor;
		ret += tor;
	}

	vramfs_sb_unlock(SB_P(inode->i_sb),spl);
	DBG_("write wrote %u",ret);
	return ret;
}

#undef vramfs_sb_lock
#undef vramfs_sb_unlock

static loff_t vramfs_llseek(struct file *f,loff_t o,int whence) {
	struct vramfs_file *pf = f->private_data;
	unsigned long spl;

	if (pf == NULL) return -EINVAL;
	spl = vramfs_sb_lock(SB_P(pf->f_ino->i_sb));

	DBG_("llseek(inode %u, offset %Ld, whence %d)",
		(unsigned int)pf->f_ino->i_ino,
		o,whence);

	switch (whence) {
		case 2:
			o += pf->f_ino->i_size;
			break;
		case 1:
			o += f->f_pos;
			break;
	};

	if (o < 0) o = 0;
	else if (o > pf->f_ino->i_size) o = pf->f_ino->i_size;

	vramfs_sb_unlock(SB_P(pf->f_ino->i_sb),spl);
	return (f->f_pos = o);
}

static void vramfs_mmap_open(struct vm_area_struct *vma) {
	DBG("mmap_close");
}

static void vramfs_mmap_close(struct vm_area_struct *vma) {
	DBG("mmap_close");
}

static struct vm_operations_struct vramfs_mmap_ops = {
	.open =			vramfs_mmap_open,
	.close =		vramfs_mmap_close,
};

static int vramfs_mmap(struct file *file,struct vm_area_struct *vma) {
	size_t size = vma->vm_end - vma->vm_start;
	struct vramfs_file *pf = file->private_data;
	struct vramfs_sb_priv *sbp;
	struct vramfs_inode *vi;
	struct super_block *sb;
	struct inode *inode;
	if (pf == NULL) return -ENOENT;
	inode = pf->f_ino;
	if (inode == NULL) return -ENOENT;
	sb = inode->i_sb;
	sbp = SB_P(sb);
	if (!sbp->allow_mmap) return -EINVAL;
	vi = get_vram_inode_entry(sbp,inode->i_ino);
	if (vi == NULL) return -ENOENT;

	DBG_("mmap vm_start=0x%08X",(unsigned int)vma->vm_start);

	vma->vm_ops = &vramfs_mmap_ops;

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff + (sbp->vram_base >> PAGE_SHIFT) + vi->first_block, size, vma->vm_page_prot)) {
		DBG("mmap fail");
		return -EAGAIN;
	}

	DBG("mmap OK");
	return 0;
}

static int vramfs_ioctl(struct inode *inode,struct file *file,unsigned int code,unsigned long arg) {
	struct super_block *sb = inode->i_sb;
	struct vramfs_sb_priv *sbp = SB_P(sb);
	struct vramfs_inode *vi = get_vram_inode_entry(sbp,inode->i_ino);

	if (code == VRAMFS_IOCTL_GET_FIRST_BLOCK) { /* return corresponding start block */
		int bofs = vi->first_block;
		return put_user(bofs,(int*)arg);
	}
	else if (code == VRAMFS_IOCTL_RESERVE_BLOCKS) { /* reserve or unreserve blocks */
		struct vramfs_reserve_blocks rb;
		int ino;

		if (!capable(CAP_SYS_ADMIN)) return -EPERM;
		if (copy_from_user(&rb,(struct vramfs_reserve_blocks __user*)arg,sizeof(rb))) return -EIO;

		for (ino=rb.first;ino <= rb.last && ino < sbp->blocks;ino++)
			sbp->bmap_reserved[ino] = rb.reserve;

		return 0;
	}
	else if (code == VRAMFS_IOCTL_IS_RESERVED) {
		int ino;

		/* we don't care if non-root can query this */
		if (get_user(ino,(int*)arg)) return -EIO;
		if (ino < 0 || ino >= sbp->blocks) return -EINVAL;
		return sbp->bmap_reserved[ino];
	}
	else if (code == VRAMFS_IOCTL_IS_OCCUPIED) {
		int ino;

		/* we don't care if non-root can query this */
		if (get_user(ino,(int*)arg)) return -EIO;
		if (ino < 0 || ino >= sbp->blocks) return -EINVAL;
		return sbp->bmap[ino];
	}

	return -EINVAL;
}

static struct file_operations vramfs_dir_fops = {
	.readdir =		vramfs_readdir,
	.open =			vramfs_open,
	.release =		vramfs_release
};

static struct file_operations vramfs_file_fops = {
	.readdir =		vramfs_readdir,
	.open =			vramfs_open,
	.read =			vramfs_read,
	.mmap =			vramfs_mmap,
	.write =		vramfs_write,
	.ioctl =		vramfs_ioctl,
	.llseek =		vramfs_llseek,
	.release =		vramfs_release
};

static struct file_operations vramfs_symlink_fops = {
	.readdir =		vramfs_readdir,
	.open =			vramfs_open,
	.release =		vramfs_release
};

struct inode *vramfs_iget(struct super_block *sb,unsigned long ino) {
	struct inode *inode = iget_locked(sb,ino);
	struct vramfs_sb_priv *sbp = SB_P(sb);
	struct vramfs_inode *vi = get_vram_inode_entry(sbp,ino);

/*	DBG_("vramfs_get(inode %lu)",ino);
	DBG_("   inode=%p",inode);
	DBG_("   sb=   %p",sb);
	DBG_("   sbp=  %p",sbp);
	DBG_("   vi=   %p",vi); */

	if (!inode) {
		DBG_("  iget_locked(%lu) failed",ino);
		return ERR_PTR(-ENOMEM);
	}

	if (!vi) {
		DBG_("  get_vram_inode_entry(%lu) failed",ino);
		iget_failed(inode);
		return ERR_PTR(-ENOENT);
	}

/*	DBG_("   inode state=0x%04lX",inode->i_state); */

	if (!(inode->i_state & I_NEW)) {
/*		DBG_("inode %lu not new",ino); */
		return inode;
	}

	switch (vi->mode & S_IFMT) {
		case S_IFDIR:
			inode->i_op = &vramfs_dir_iops;
			inode->i_fop = &vramfs_dir_fops;
			break;
		case S_IFREG:
			inode->i_op = &vramfs_file_iops;
			inode->i_fop = &vramfs_file_fops;
			break;
		case S_IFLNK:
			inode->i_op = &vramfs_symlink_iops;
			inode->i_fop = &vramfs_symlink_fops;
			break;
	}
	inode->i_mode = vi->mode;
	inode->i_uid = vi->uid;
	inode->i_gid = vi->gid;
	inode->i_size = vi->size;
	inode->i_blocks = (vi->size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	inode->i_nlink = (vi->mode & S_IFMT) == S_IFDIR ? 2 : 1;
	inode->i_atime = vi->atime;
	inode->i_ctime = vi->ctime;
	inode->i_mtime = vi->mtime;

	unlock_new_inode(inode);
	return inode;
}

/* call this with spinlock held */
static struct inode *vramfs_create_inode(struct inode *parent_inode,int mode,const char *name) {
	struct super_block *sb = parent_inode->i_sb;
	struct vramfs_sb_priv *sbp = SB_P(sb);
	struct vramfs_inode *vi_empty=NULL;
	struct vramfs_inode *vi;
	int namel=strlen(name);
	struct inode *inode;
	int ino_empty = 0;
	int ino;

	/* scan #1: does it already exist? */
	for (ino=INODE_BASE;ino < sbp->inode_max+INODE_BASE;ino++) {
		vi = get_vram_inode_entry(sbp,ino);
		if (vi == NULL) continue;
		if (vi->vi_sb == NULL) {
			if (vi_empty == NULL) {
				ino_empty = ino;
				vi_empty = vi; /* that's the one we take */
			}
			continue;
		}
		if (vi->parent != parent_inode->i_ino) continue;
		if (vi->name == NULL) continue;
		if (!strcmp(vi->name,name))
			return ERR_PTR(-EEXIST);
	}

	vi = vi_empty;
	if (!vi) return ERR_PTR(-ENOSPC);

	memset(vi,0,sizeof(*vi));

	vi->vi_sb = sb;
	vi->first_block = -1;
	vi->mode = mode;
	vi->size = ((mode & S_IFMT) == S_IFDIR) ? PAGE_SIZE : 0;
	vi->uid = current->fsuid;
	vi->gid = current->fsgid;
	vi->atime = vi->ctime = vi->mtime = CURRENT_TIME;
	vi->parent = parent_inode->i_ino;

	vi->name = kmalloc(namel+1,GFP_KERNEL);
	if (!vi->name) {
		vi->vi_sb = NULL;
		return ERR_PTR(-ENOMEM);
	}
	memcpy(vi->name,name,namel+1);

	inode = vramfs_iget(sb,ino_empty);
	if (IS_ERR(inode)) {
		vi->vi_sb = NULL;
		kfree(vi->name);
		return inode;
	}

	return inode;
}

enum {
	Opt_phys_range,
	Opt_length,
	Opt_pci,
	Opt_mmap_off,
	Opt_mmap_on,
	Opt_framebuffer,
	Opt_error
};

static match_table_t vramfs_tokens = {
	{Opt_phys_range,	"physical=%u"},
	{Opt_length,		"length=%u"},
	{Opt_pci,		"pci=%s"},
	{Opt_mmap_off,		"mmap=0"},
	{Opt_mmap_on,		"mmap=1"},
	{Opt_framebuffer,	"framebuffer=%u"},
	{Opt_error,		NULL}
};

static int vramfs_pci_dev(substring_t arg,uint64_t *base,int *blocks) {
	struct pci_bus *bus = NULL;
	struct pci_dev *dev = NULL;
	int ret=-1,domain=0,busno=0;
	int slot=-1,function=0;
	char *fence = arg.to;
	char *p = arg.from;
	int i=0;

	while (p < fence) {
		if (*p == ':') {
			p++;
			i++;
		}
		else if (*p == ' ')
			p++;
		/* what? no isxdigit()? */
		else if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
			int val = simple_strtoul(p,&p,0);
			switch (i) {
				case 0:	domain = val;	break;
				case 1: busno = val;	break;
				case 2:	slot = val;	break;
				case 3:	function = val;	break;
			}
		}
		else {
			ret = -1;
			break;
		}
	}

	if (slot >= 0) {
		DBG_("pci device requested: %d:%d:%d:%d",domain,busno,slot,function);

		if ((bus = pci_find_bus(domain,busno)) != NULL) {
			DBG("found PCI bus");
			if ((dev = pci_get_slot(bus,PCI_DEVFN(slot,function))) != NULL) {
				DBG("found PCI device");
				/* make sure it's VGA-class */
				if ((dev->class & 0xFF0000) != 0x030000) {
					DBG("PCI device is not VGA-class");
				}
				else {
					/* scan BARs and look for the memory range that is marked
					 * prefetchable and is larger than 1MB. on all test machines
					 * I have, this is the framebuffer (the MMIO register area
					 * is usually the 64KB area) */
					struct resource *res;
					int resi;

					for (resi=0;resi < PCI_ROM_RESOURCE;resi++) {
						res = &dev->resource[resi];
						if ((res->start+0x100000) <= res->end && /* >= 1MB */
							(res->flags & IORESOURCE_MEM) &&
							(res->flags & IORESOURCE_PREFETCH) &&
							!(res->flags & IORESOURCE_DISABLED) &&
							res->start != 0) {
							DBG_("Found PCI resource %u that looks like framebuffer",resi);
							*base = res->start;
							*blocks = ((res->end - res->start) + PAGE_SIZE) >> PAGE_SHIFT;
							ret = 0;
							break;
						}
					}
				}
			}
		}
	}

	if (dev != NULL) pci_dev_put(dev);
	return ret;
}

static int fill_super(struct super_block *sb, void *data, int flags) {
	struct vramfs_sb_priv *sbp;
	struct vramfs_inode *vroot;
	struct inode *root;
	char *p,*opts = (char*)data,*junk;
	int framebuffer_blocks = 0;

	int mmap = default_mmap;
	int blocks = fake_blocks;
	uint64_t vram_base = fake_vram;

	/* you must be root to mount with this driver */
	if (!capable(CAP_SYS_ADMIN)) return -EINVAL;

	if (opts) {
		substring_t args[MAX_OPT_ARGS];
		while ((p = strsep(&opts,",")) != NULL) {
			int token;

			if (*p == 0)
				continue;

			token = match_token(p, vramfs_tokens, args);
			switch (token) {
				case Opt_framebuffer:
					framebuffer_blocks =
						(simple_strtoul(args[0].from,&junk,0) + PAGE_SIZE - 1) >> PAGE_SHIFT;
					break;
				case Opt_phys_range:
					vram_base = simple_strtoul(args[0].from,&junk,0);
					break;
				case Opt_length:
					blocks = (simple_strtoul(args[0].from,&junk,0) + PAGE_SIZE - 1) >> PAGE_SHIFT;
					break;
				case Opt_pci:
					if (vramfs_pci_dev(args[0],&vram_base,&blocks)) {
						printk(KERN_ERR "vramfs: cannot locate or map pci device\n");
						return -ENODEV;
					}
					break;
				case Opt_mmap_off:
					mmap=0;
					break;
				case Opt_mmap_on:
					mmap=1;
					break;
				default:
					printk(KERN_ERR "vramfs: unknown token %s\n",p);
			}
		}
	}

	if (framebuffer_blocks > blocks)
		framebuffer_blocks = blocks;

	if (framebuffer_blocks > 0)
		DBG_("framebuffer blocks %d",framebuffer_blocks);

	if (blocks < 4 || blocks > (0x7FFFFFFF >> PAGE_SHIFT))
		return -EINVAL;

	if (vram_base == 0) {
		printk(KERN_WARNING "vramfs: no device given and fake vram not enabled. Refusing to mount nothing\n");
		return -EINVAL;
	}

	if (vram_base == fake_vram && blocks > fake_blocks)
		blocks = fake_blocks;

	if ( !(sbp = kzalloc(sizeof(*sbp), GFP_KERNEL)) )
		return -ENOMEM;

	if (init_sb_priv(sbp,blocks,vram_base)) {
		kfree(sbp);
		return -ENOMEM;
	}

	sbp->allow_mmap = mmap;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = VRAMFS_MAGIC;
	sb->s_op = &vramfs_sops;
	sb->s_type = &fst_vramfs;
	sb->s_fs_info = sbp;

	vroot = get_vram_inode_entry(sbp, INODE_ROOT);
	if (!vroot) {
		DBG("initing root: cannot get inode root");
		kfree(sbp);
		return -ENOMEM;
	}
	vroot->vi_sb = sb;
	vroot->mode = S_IFDIR|0777;
	vroot->size = PAGE_SIZE;
	vroot->uid = current->fsuid;
	vroot->gid = current->fsgid;
	vroot->atime = vroot->ctime = vroot->mtime =
		CURRENT_TIME;

	root = vramfs_iget(sb, INODE_ROOT);
	if (IS_ERR(root)) {
		kfree(sbp);
		return (size_t)root;
	}

	DBG_("root inode: %u",(unsigned int)root->i_ino);

	if (!(sb->s_root = d_alloc_root(root))) {
		iput(root);
		kfree(sbp);
		return -ENOMEM;
	}

	if (framebuffer_blocks > 0) {
		/* create a "senty" file to section off the part of the VRAM used by the
		 * Linux framebuffer console, so copy operations to this fs do not throw
		 * garbage all over the screen */
		struct inode *inode =
			vramfs_create_inode(root,S_IFREG|0600,"framebuffer");
		if (inode) {
			int bn;
			int ino = inode->i_ino;
			struct vramfs_inode *vi = get_vram_inode_entry(sbp,ino);
			if (vi) {
				vi->size = inode->i_size = framebuffer_blocks * PAGE_SIZE;
				vi->first_block = 0;
				for (bn=0;bn < framebuffer_blocks;bn++)
					sbp->bmap[bn] = inode->i_ino;
			}
			iput(inode);
		}
	}

	return 0;
}

static int __init vramfs_init(void) {
	if (enable_fake_vram && init_fake_vram())
		return -ENOMEM;
	if (register_filesystem(&fst_vramfs))
		return -ENODEV;

	printk(KERN_INFO "vramfs filesystem driver "
		"(C) 2008 Jonathan Campbell\n");

	return 0; /* OK */
}

static void __exit vramfs_cleanup(void) {
	unregister_filesystem(&fst_vramfs);
	free_fake_vram();
}

module_init(vramfs_init);
module_exit(vramfs_cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonathan Campbell");
MODULE_DESCRIPTION("vramfs filesystem driver");

