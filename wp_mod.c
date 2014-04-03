#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/mmu_writeable.h>

#define DRIVER_AUTHOR "flar2"
#define DRIVER_DESCRIPTION "Defeat system write protect"
#define DRIVER_VERSION "4.1"

#define MSM_MAX_PARTITIONS 48
#define HIJACK_SIZE 12

struct htc_emmc_partition {
	unsigned int dev_num;
	unsigned int partition_size;
	char partition_name[16];
};

static struct htc_emmc_partition emmc_partitions[MSM_MAX_PARTITIONS];


static int my_get_partition_num_by_name(char *name)
{
	struct htc_emmc_partition *ptn = emmc_partitions;
	int i;
	char caller[80];

	sprintf(caller, "%ps", __builtin_return_address(0));

	if (strcmp("generic_make_request_checks", caller) == 0) {
		return 666;
	} else {
		for (i = 0; i < MSM_MAX_PARTITIONS && ptn->partition_name; i++, ptn++) {
			if (strcmp(ptn->partition_name, name) == 0)
				return ptn->dev_num;
		}
	}

	return -1;
}

inline void arm_write_hook ( void *target, char *code )
{
    unsigned long *target_arm = (unsigned long *)target;
    unsigned long *code_arm = (unsigned long *)code;

    mem_text_write_kernel_word(target_arm, *code_arm);
    mem_text_write_kernel_word(target_arm + 1, *(code_arm + 1));
    mem_text_write_kernel_word(target_arm + 2, *(code_arm + 2));
}


void hijack_start ( void *target, void *new )
{
    unsigned char n_code[HIJACK_SIZE];

    //ldr pc, [pc, #0]; .long addr; .long addr
    memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);
    *(unsigned long *)&n_code[4] = (unsigned long)new;
    *(unsigned long *)&n_code[8] = (unsigned long)new;

    pr_info("Hooking function 0x%p with 0x%p\n", target, new);

    arm_write_hook(target, n_code);
}

static int __init wp_mod_init(void)
{
	pr_info("wp_mod: %s version %s\n", DRIVER_DESCRIPTION,
		DRIVER_VERSION);
	pr_info("wp_mod: by %s\n", DRIVER_AUTHOR);

	hijack_start((void *)kallsyms_lookup_name("get_partition_num_by_name"), &my_get_partition_num_by_name);

	return 0;
}

module_init(wp_mod_init)

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
