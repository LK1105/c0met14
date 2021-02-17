//
//  sandbox_util.h
//  c0met_light
//
//  Created by maverickdev1 on 17.02.2021.
//

#ifndef sandbox_util_h
#define sandbox_util_h

uint64_t disable_sandbox(uint64_t task);
uint64_t cicuta_virosa(void);

uint64_t read_64(uint64_t addr);

uint32_t read_32(uint64_t addr);

void write_20(uint64_t addr, const void* buf);

void write_32(uint64_t addr, const void* buf);

void write_64(uint64_t addr, const void* buf);



#endif /* sandbox_util_h */
