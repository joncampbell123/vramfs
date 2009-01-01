
#define VRAMFS_IOCTL_GET_FIRST_BLOCK	0x100
#define VRAMFS_IOCTL_RESERVE_BLOCKS	0x101
#define VRAMFS_IOCTL_IS_RESERVED	0x102
#define VRAMFS_IOCTL_IS_OCCUPIED	0x103

struct vramfs_reserve_blocks {
	int		first,last;
	uint8_t		reserve;
};

