
MODULE_NAME = ref_monitor

obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-objs += reference_monitor.o crypto/sha256.o utils/utils.o probes/probes.o task/tasks.o path_list/path_list.o

all:

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:

	sudo insmod $(MODULE_NAME).ko the_file=$(realpath ./singlefile-FS/mount/the-file) #module_name=$(MODULE_NAME)
	sudo mknod /dev/$(MODULE_NAME) c 237 0

unload:

	sudo rmmod $(MODULE_NAME)
	sudo rm -rf /dev/$(MODULE_NAME)
