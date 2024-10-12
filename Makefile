
obj-m += ref_monitor.o

# Specifica quali file oggetto costruire per il modulo
ref_monitor-objs += reference_monitor.o crypto/sha256.o utils/utils.o probes/probes.o task/tasks.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


load:
	sudo insmod ref_monitor.ko the_file=$(realpath ./singlefile-FS/mount/the-file)
	sudo mknod /dev/ref_monitor c 237 0

unload:
	sudo rmmod ref_monitor
	sudo rm -rf /dev/ref_monitor
