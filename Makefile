obj-m += vramfs.o

ifndef $(KDIR)
KDIR=/usr/src/2.6.27.9
endif

all:
	make -C $(KDIR) M=$(PWD) modules

install:
	make -C $(KDIR) M=$(PWD) modules_install

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f modules.order

