#ifndef _LDASM_
#define _LDASM_

#include <stdint.h>

#define	F_INVALID		0x01
#define F_PREFIX		0x02
#define	F_REX			0x04
#define F_MODRM			0x08
#define F_SIB			0x10
#define F_DISP			0x20
#define F_IMM			0x40
#define F_RELATIVE		0x80


typedef struct _ldasm_data{
	uint8_t		flags;
	uint8_t		rex;
	uint8_t		modrm;
	uint8_t		sib;
	uint8_t		opcd_offset;
	uint8_t		opcd_size;
	uint8_t		disp_offset;
	uint8_t		disp_size;
	uint8_t		imm_offset;
	uint8_t		imm_size;
} ldasm_data;

unsigned int ldasm(void *code, ldasm_data *ld, uint32_t is64);

#endif /* _LDASM_ */
