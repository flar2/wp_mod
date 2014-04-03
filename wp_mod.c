#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <asm/mmu_writeable.h>

#define DRIVER_AUTHOR "flar2"
#define DRIVER_DESCRIPTION "Defeat system write protect"
#define DRIVER_VERSION "4.0"

#define MSM_MAX_PARTITIONS 48
#define HIJACK_SIZE 12

char *system_part[] = {"system"};

unsigned long addr_get_partition_num_by_name;

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

	if (strcmp(system_part[0], name) == 0) {
		pr_debug("Allow write to system\n");
	   	return 666;
	} else {
		for (i = 0; i < MSM_MAX_PARTITIONS && ptn->partition_name; i++, ptn++) {
			if (strcmp(ptn->partition_name, name) == 0)
				return ptn->dev_num;
		}
	}

	return -1;
}


struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

struct ksym {
    char *name;
    unsigned long addr;
};

LIST_HEAD(hooked_syms);


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
    struct sym_hook *sa;
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];

    if ( (unsigned long)target % 4 == 0 )
    {
        // ldr pc, [pc, #0]; .long addr; .long addr
        memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[4] = (unsigned long)new;
        *(unsigned long *)&n_code[8] = (unsigned long)new;
    }
    else
    {
        // add r0, pc, #4; ldr r0, [r0, #0]; mov pc, r0; mov pc, r0; .long addr
        memcpy(n_code, "\x01\xa0\x00\x68\x87\x46\x87\x46\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[8] = (unsigned long)new;
        target--;
    }

    pr_info("Hooking function 0x%p with 0x%p\n", target, new);

    memcpy(o_code, target, HIJACK_SIZE);

    arm_write_hook(target, n_code);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if ( ! sa )
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

    list_add(&sa->list, &hooked_syms);
}


void hijack_stop ( void *target )
{
    struct sym_hook *sa;

    pr_info("Unhooking function 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            arm_write_hook(target, sa->o_code);

            list_del(&sa->list);
            kfree(sa);
            break;
        }
}


static int __init wp_mod_init(void)
{
	pr_info("wp_mod: %s version %s\n", DRIVER_DESCRIPTION,
		DRIVER_VERSION);
	pr_info("wp_mod: by %s\n", DRIVER_AUTHOR);

	addr_get_partition_num_by_name = kallsyms_lookup_name("get_partition_num_by_name");
	hijack_start((void *)addr_get_partition_num_by_name, &my_get_partition_num_by_name);

	return 0;
}


static void __exit wp_mod_exit(void)
{
	hijack_stop((void *)addr_get_partition_num_by_name);
}

module_init(wp_mod_init)
module_exit(wp_mod_exit)

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
