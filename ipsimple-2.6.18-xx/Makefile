# 

TARGET:= ipsimple.ko

all: ${TARGET}

ipsimple.ko: ip_sm_compat.c  ipsimple_core.h  ipsimple_core.c
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 modules

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 clean

install: ${TARGET}
	cp -p ${TARGET} /lib/modules/`uname -r`/kernel/net/netfilter; depmod -a

obj-m := ipsimple.o

ipsimple-objs := ip_sm_compat.o ipsimple_core.o

clean-files := *.o *.ko *.mod.[co] *~
