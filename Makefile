
obj-m += ref_monitor.o

# Specifica quali file oggetto costruire per il modulo
ref_monitor-objs += reference_monitor.o crypto/sha256.o utils/utils.o probes/probes.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


load:
	sudo insmod reference_monitor.ko the_file=$(realpath ./singlefile-FS/mount/the-file)
	sudo mknod /dev/reference_monitor c 237 0

unload:
	sudo rmmod reference_monitor
	sudo rm -rf /dev/reference_monitor
