//
//  ViewController.m
//  c0metjb_rc1
//
//  Created by Ali on 15.02.2021.
//

#import "ViewController.h"
#import "cicuta_virosa.h"
#import <assert.h>
#import <stdlib.h>
#import <pthread.h>
#import <stdio.h>
#import <unistd.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <errno.h>
#import "cicuta_virosa.h"
#import "voucher_utils.h"
#import "cicuta_log.h"
#import "descriptors_utils.h"
#import "fake_element_spray.h"
#import "exploit_utilities.h"
#import "comet.h"
#import "fishhook.h"
#import "BypassAntiDebugging.h"
@interface ViewController ()
@property (strong, nonatomic) IBOutlet UILabel *ver_stat;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *currSysVer = [[UIDevice currentDevice] systemVersion];
   
    _ver_stat.self.text=currSysVer;
    disable_pt_deny_attach();
    disable_sysctl_debugger_checking();
        
    #if TESTS_BYPASS
    test_aniti_debugger();
    #endif
    
}

- (IBAction)post_exploit:(UIButton *)sender {
  
    installBootstrapAndUnsadbox(nil); //this will bypass sandbox
}



@end
