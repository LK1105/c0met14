//
//  jb_BridgingHeader.h
//  c0met_light
//
//  Created by Ali on 17.02.2021.
//
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <sys/snapshot.h>
#import "cicuta_virosa.h"
#import "sandbox_util.h"
#import "BypassAntiDebugging.h"

#ifndef jb_BridgingHeader_h
#define jb_BridgingHeader_h

//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//
uint64_t cicuta_virosa(void);

uint64_t read_64(uint64_t addr);

uint32_t read_32(uint64_t addr);

void write_20(uint64_t addr, const void* buf);

void write_32(uint64_t addr, const void* buf);

void write_64(uint64_t addr, const void* buf);

uint64_t killsandbox(uint64_t task);

#endif /* jb_BridgingHeader_h */
