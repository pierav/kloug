bootrom_img = bootrom.img

CC       = riscv64-unknown-elf-gcc
OBJCOPY	 = riscv64-unknown-elf-objcopy
DTB      = kloug.dtb


all: bootrom.img gen/c/bootrom.h

%.img: %.bin
	dd if=$< of=$@ bs=128

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

%.elf: %.S link.ld $(DTB)
	$(CC) -Tlink.ld -march=rv32i -mabi=ilp32 $< -nostdlib -static -Wl,--no-gc-sections -o $@

%.dtb: %.dts
	dtc -I dts $< -O dtb -o $@

clean:
	rm -f bootrom.img bootrom.bin bootrom.elf $(DTB)

.phony: all clean
.PRECIOUS: %.img %.bin %.elf %.dtb

# Generate c header
gen/c/bootrom.h: bootrom.bin
	mkdir -p $(@D)
	xxd -i -n bootrom $< > $@