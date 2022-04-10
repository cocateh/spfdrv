obj-m += spoofer.o

all:
	make -j10 -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -j10 -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insert: spoofer.ko
	sudo insmod spoofer.ko

remove: spoofer.ko
	sudo rmmod spoofer.ko

reinsert: spoofer.ko
	sudo rmmod spoofer.ko
	sudo insmod spoofer.ko
