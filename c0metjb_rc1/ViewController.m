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
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#import <spawn.h>

#import <sys/types.h>
#import <sys/stat.h>
#import <dirent.h>

#import <sys/socket.h>
#import <sys/types.h>
#import <arpa/inet.h>
@interface ViewController ()
@property (strong, nonatomic) IBOutlet UILabel *ver_stat;
@property (strong, nonatomic) IBOutlet UIButton *jb_button;


@end

@implementation ViewController
-(void)log:(NSString*)log {
    NSLog(log);
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

- (NSURL *)applicationDocumentsDirectory
{
  return [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *currSysVer = [[UIDevice currentDevice] systemVersion];
    if([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/c0met.ini"]){
        [_jb_button setTitle:@"jailbroken" forState:UIControlStateNormal];
    }
    _ver_stat.self.text=currSysVer;
    disable_pt_deny_attach();
    disable_sysctl_debugger_checking();
        
    #if TESTS_BYPASS
    test_aniti_debugger();
    #endif
    
}
int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);
    if (rv) return rv;
    
    return 0;
    
    //int a = 0;
    //waitpid(pd, &a, 0);
    
    //return WEXITSTATUS(a);
}



- (void)installBin:(NSString *)data
{
   
    //prepare_payload();
    NSString *openFile ;
       NSFileManager *fileManager = [NSFileManager defaultManager];
       NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
       NSString *documentsDirectory = [paths objectAtIndex:0];

           

          
    NSError *error = NULL;
    NSBundle* ucache;
     
    // Obtain a reference to a loadable bundle.
    ucache = [NSBundle bundleWithPath:@"uicache"];

    cicuta_log("...");
    cicuta_log("..");
    
    sleep(1);
    cicuta_log("[+] Time to extract our bootstrap...");

    chmod(in_bundle("uicache"), 0777); //give it proper permissions
   
    copyFile(in_bundle("uicache"), "/var/mobile/uicache");
    
    launch("/var/mobile/uicache", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
   
  
}
- (IBAction)post_exploit:(UIButton *)sender {
  
    installBootstrapAndUnsadbox(nil);

    if([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/c0met.ini"]){
        cicuta_log("...");
        cicuta_log("yes yes we are in. jailbroken state unless you exit the app");
    }
    //this will bypass sandbox
    [self installBin:@"babe we are burning dat today"];
}



@end
