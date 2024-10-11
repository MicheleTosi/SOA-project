
obj-m += ref_monitor.o

# Specifica quali file oggetto costruire per il modulo
ref_monitor-objs += reference_monitor.o crypto/sha256.o utils/utils.o probes/probes.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

