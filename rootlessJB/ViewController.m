//
//  ViewController.m
//  rootlessJB
//
//  Created by Jake James on 8/28/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import "ViewController.h"
#import "jelbrekLib.h"
#import "exploit/multi_path/sploit.h"
#import "exploit/voucher_swap/voucher_swap.h"
#import "libjb.h"
#import "payload.h"
#import "offsetsDump.h"
#import "exploit/voucher_swap/kernel_slide.h"
#import "exploit/cicuta_virosa-main/cicuta_virosa.h"
#import <mach/mach.h>
#import <sys/stat.h>

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UISwitch *enableTweaks;
@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;
@property (weak, nonatomic) IBOutlet UISwitch *installiSuperSU;

@property (weak, nonatomic) IBOutlet UITextView *logs;
@end

@implementation ViewController

-(void)log:(NSString*)log {
    self.logs.text = [NSString stringWithFormat:@"%@%@", self.logs.text, log];
}

/*#define LOG(what, ...) dispatch_async(dispatch_get_main_queue(), ^{ \
                           [self log:[NSString stringWithFormat:@what"\n", ##__VA_ARGS__]];\
                           printf("\t"what"\n", ##__VA_ARGS__);\
                       })*/

#define LOG(what, ...) [self log:[NSString stringWithFormat:@what"\n", ##__VA_ARGS__]];\
                        printf("\t"what"\n", ##__VA_ARGS__)

#define in_bundle(obj) strdup([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@obj] UTF8String])

#define failIf(condition, message, ...) if (condition) {\
                                            LOG(message);\
                                            goto end;\
                                        }
#define maxVersion(v)  ([[[UIDevice currentDevice] systemVersion] compare:@v options:NSNumericSearch] != NSOrderedDescending)


#define fileExists(file) [[NSFileManager defaultManager] fileExistsAtPath:@(file)]
#define removeFile(file) if (fileExists(file)) {\
                            [[NSFileManager defaultManager]  removeItemAtPath:@file error:&error]; \
                            if (error) { \
                                LOG("[-] Error: removing file %s (%s)", file, [[error localizedDescription] UTF8String]); \
                                error = NULL; \
                            }\
                         }

#define copyFile(copyFrom, copyTo) [[NSFileManager defaultManager] copyItemAtPath:@(copyFrom) toPath:@(copyTo) error:&error]; \
                                   if (error) { \
                                       LOG("[-] Error copying item %s to path %s (%s)", copyFrom, copyTo, [[error localizedDescription] UTF8String]); \
                                       error = NULL; \
                                   }

#define moveFile(copyFrom, moveTo) [[NSFileManager defaultManager] moveItemAtPath:@(copyFrom) toPath:@(moveTo) error:&error]; \
                                   if (error) {\
                                       LOG("[-] Error moviing item %s to path %s (%s)", copyFrom, moveTo, [[error localizedDescription] UTF8String]); \
                                       error = NULL; \
                                   }

- (void)viewDidLoad {
    [super viewDidLoad];
    if (!maxVersion("14.0") && maxVersion("14.3")) {
        [[self enableTweaks] setOn:false];
        [[self enableTweaks] setEnabled:false];
        [[self installiSuperSU] setOn:false];
        [[self installiSuperSU] setEnabled:false];
    }
    // Do any additional setup after loading the view, typically from a nib.
}
- (IBAction)jb:(UIButton *)sender {
    cicuta_virosa();
}

- (IBAction)jailbrek:(id)sender {
    
    

}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
