#ifndef CODE_SWAP_HSI_H
#define CODE_SWAP_HSI_H

#define SWIM_STACK_SIZE 10
typedef enum swim_id {
	SWIM_NONE = 0,
	SWIM_ID1 = 1,
	SWIM_ID2 = 2,
	SWIM_ID3 = 3,
	SWIM_ID4 = 4,
	SWIM_ID5 = 5,
	SWIM_ID6 = 6,
	SWIM_ID7 = 7,
	SWIM_ID8 = 8,
	SWIM_MAX
}swim_id_t;

// Single image descriptor, populated in BC1, and is used for loading the images
typedef struct swim_img_info {
    u32 nvm_offset;
    u32 image_size;
    u32 stat_times_loaded;
    u32 stat_times_load_not_required;
    u32 stat_times_load_failed;
    u32 stored_gp_val;
}swim_img_info_t;

// The meta data on the swappable images
typedef struct swim_stack {
    u32_t       img_stack[SWIM_STACK_SIZE];
    u32_t       cur_img_stack_id;
}swim_stack_t;

typedef struct swim_meta {
    swim_img_info_t info[SWIM_MAX];
    // Image Stack

    u32_t      swim_group;
    #define SWIM_GROUP_A 1
    #define SWIM_GROUP_B 2
    #define SWIM_GROUP_INVALID 0

    u32_t      cur_loaded_swim;
 }swim_meta_t;

#endif /* CODE_SWAP_HSI_H */
