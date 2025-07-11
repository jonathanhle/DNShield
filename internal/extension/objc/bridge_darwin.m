#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <SystemExtensions/SystemExtensions.h>

// Global references for DNS proxy management
static NEDNSProxyManager *_dnsProxyManager = nil;
static NSArray<NSString *> *_blockedDomains = nil;
static dispatch_semaphore_t _installSemaphore = nil;
// Remove unused global variable

// System Extension Delegate
@interface DNShieldSystemExtensionDelegate : NSObject <OSSystemExtensionRequestDelegate>
@property (nonatomic, strong) dispatch_semaphore_t semaphore;
@property (nonatomic) OSSystemExtensionRequestResult lastResult;
@end

@implementation DNShieldSystemExtensionDelegate

- (instancetype)init {
    self = [super init];
    if (self) {
        _semaphore = dispatch_semaphore_create(0);
        // Initialize to a valid enum value
        _lastResult = (OSSystemExtensionRequestResult)0;
    }
    return self;
}

- (void)request:(OSSystemExtensionRequest *)request didFinishWithResult:(OSSystemExtensionRequestResult)result {
    NSLog(@"DNShield: System extension request finished with result: %ld", (long)result);
    self.lastResult = result;
    dispatch_semaphore_signal(self.semaphore);
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
    NSLog(@"DNShield: System extension request failed: %@", error.localizedDescription);
    self.lastResult = (OSSystemExtensionRequestResult)0; // Request failed
    dispatch_semaphore_signal(self.semaphore);
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
    NSLog(@"DNShield: System extension requires user approval in System Preferences > Privacy & Security");
    // Note: The request is still pending, don't signal semaphore yet
}

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request actionForReplacingExtension:(NSString *)existing 
      withExtension:(NSString *)ext {
    NSLog(@"DNShield: Replacing existing extension %@ with %@", existing, ext);
    // Allow replacement
    return OSSystemExtensionReplacementActionReplace;
}

@end

// C Bridge Functions Implementation

int installSystemExtensionBridge(const char* bundleID) {
    @autoreleasepool {
        NSString *extensionBundleID = [NSString stringWithUTF8String:bundleID];
        
        DNShieldSystemExtensionDelegate *delegate = [[DNShieldSystemExtensionDelegate alloc] init];
        
        OSSystemExtensionRequest *request = [OSSystemExtensionRequest 
            activationRequestForExtension:extensionBundleID 
            queue:dispatch_get_main_queue()];
        request.delegate = delegate;
        
        [[OSSystemExtensionManager sharedManager] submitRequest:request];
        
        // Wait for completion with timeout (60 seconds)
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(delegate.semaphore, timeout) != 0) {
            NSLog(@"DNShield: Installation timed out");
            return -2; // Timeout
        }
        
        return delegate.lastResult == OSSystemExtensionRequestCompleted ? 0 : -1;
    }
}

int uninstallSystemExtensionBridge(const char* bundleID) {
    @autoreleasepool {
        NSString *extensionBundleID = [NSString stringWithUTF8String:bundleID];
        
        DNShieldSystemExtensionDelegate *delegate = [[DNShieldSystemExtensionDelegate alloc] init];
        
        OSSystemExtensionRequest *request = [OSSystemExtensionRequest 
            deactivationRequestForExtension:extensionBundleID 
            queue:dispatch_get_main_queue()];
        request.delegate = delegate;
        
        [[OSSystemExtensionManager sharedManager] submitRequest:request];
        
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(delegate.semaphore, timeout) != 0) {
            NSLog(@"DNShield: Uninstallation timed out");
            return -2; // Timeout
        }
        
        return delegate.lastResult == OSSystemExtensionRequestCompleted ? 0 : -1;
    }
}

int startDNSProxyBridge(const char* bundleID, char** domains, int domainCount) {
    @autoreleasepool {
        NSString *extensionBundleID = [NSString stringWithUTF8String:bundleID];
        
        // Convert C string array to NSArray
        NSMutableArray<NSString *> *blockedDomainsList = [NSMutableArray arrayWithCapacity:domainCount];
        for (int i = 0; i < domainCount; i++) {
            NSString *domain = [NSString stringWithUTF8String:domains[i]];
            if (domain) {
                [blockedDomainsList addObject:domain];
            }
        }
        _blockedDomains = [blockedDomainsList copy];
        
        // Load DNS proxy manager
        dispatch_semaphore_t loadSemaphore = dispatch_semaphore_create(0);
        __block BOOL loadSuccess = NO;
        
        [NEDNSProxyManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NEDNSProxyManager *> * _Nullable managers, NSError * _Nullable error) {
            if (error) {
                NSLog(@"DNShield: Failed to load DNS proxy managers: %@", error.localizedDescription);
            } else {
                // Find existing or create new
                for (NEDNSProxyManager *manager in managers) {
                    NEDNSProxyProviderProtocol *protocol = (NEDNSProxyProviderProtocol *)manager.providerProtocol;
                    if (protocol && [protocol.providerBundleIdentifier isEqualToString:extensionBundleID]) {
                        _dnsProxyManager = manager;
                        break;
                    }
                }
                
                if (!_dnsProxyManager) {
                    _dnsProxyManager = [[NEDNSProxyManager alloc] init];
                    NEDNSProxyProviderProtocol *providerProtocol = [[NEDNSProxyProviderProtocol alloc] init];
                    providerProtocol.providerBundleIdentifier = extensionBundleID;
                    providerProtocol.providerConfiguration = @{
                        @"blockedDomains": _blockedDomains
                    };
                    _dnsProxyManager.providerProtocol = providerProtocol;
                    _dnsProxyManager.localizedDescription = @"DNShield DNS Filter";
                }
                
                loadSuccess = YES;
            }
            dispatch_semaphore_signal(loadSemaphore);
        }];
        
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(loadSemaphore, timeout) != 0 || !loadSuccess) {
            NSLog(@"DNShield: Failed to load DNS proxy manager");
            return -1;
        }
        
        // Enable and save
        _dnsProxyManager.enabled = YES;
        
        dispatch_semaphore_t saveSemaphore = dispatch_semaphore_create(0);
        __block BOOL saveSuccess = NO;
        
        [_dnsProxyManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if (error) {
                NSLog(@"DNShield: Failed to save DNS proxy configuration: %@", error.localizedDescription);
            } else {
                NSLog(@"DNShield: DNS proxy configuration saved successfully");
                saveSuccess = YES;
            }
            dispatch_semaphore_signal(saveSemaphore);
        }];
        
        timeout = dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(saveSemaphore, timeout) != 0 || !saveSuccess) {
            NSLog(@"DNShield: Failed to save DNS proxy configuration");
            return -1;
        }
        
        return 0;
    }
}

int stopDNSProxyBridge(void) {
    @autoreleasepool {
        if (!_dnsProxyManager) {
            NSLog(@"DNShield: No DNS proxy manager to stop");
            return -1;
        }
        
        _dnsProxyManager.enabled = NO;
        
        dispatch_semaphore_t saveSemaphore = dispatch_semaphore_create(0);
        __block BOOL success = NO;
        
        [_dnsProxyManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if (error) {
                NSLog(@"DNShield: Failed to disable DNS proxy: %@", error.localizedDescription);
            } else {
                NSLog(@"DNShield: DNS proxy disabled successfully");
                success = YES;
            }
            dispatch_semaphore_signal(saveSemaphore);
        }];
        
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(saveSemaphore, timeout) != 0 || !success) {
            return -1;
        }
        
        return 0;
    }
}

int updateDNSProxyDomainsBridge(char** domains, int domainCount) {
    @autoreleasepool {
        if (!_dnsProxyManager) {
            NSLog(@"DNShield: No DNS proxy manager to update");
            return -1;
        }
        
        // Convert new domains
        NSMutableArray<NSString *> *newDomains = [NSMutableArray arrayWithCapacity:domainCount];
        for (int i = 0; i < domainCount; i++) {
            NSString *domain = [NSString stringWithUTF8String:domains[i]];
            if (domain) {
                [newDomains addObject:domain];
            }
        }
        _blockedDomains = [newDomains copy];
        
        // Update configuration
        NEDNSProxyProviderProtocol *providerProtocol = (NEDNSProxyProviderProtocol *)_dnsProxyManager.providerProtocol;
        providerProtocol.providerConfiguration = @{
            @"blockedDomains": _blockedDomains
        };
        
        // Save updated configuration
        dispatch_semaphore_t saveSemaphore = dispatch_semaphore_create(0);
        __block BOOL success = NO;
        
        [_dnsProxyManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if (error) {
                NSLog(@"DNShield: Failed to update DNS proxy domains: %@", error.localizedDescription);
            } else {
                NSLog(@"DNShield: DNS proxy domains updated successfully");
                success = YES;
            }
            dispatch_semaphore_signal(saveSemaphore);
        }];
        
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(saveSemaphore, timeout) != 0 || !success) {
            return -1;
        }
        
        return 0;
    }
}

int isExtensionInstalledBridge(const char* bundleID) {
    @autoreleasepool {
        NSString *extensionBundleID = [NSString stringWithUTF8String:bundleID];
        
        dispatch_semaphore_t checkSemaphore = dispatch_semaphore_create(0);
        __block BOOL installed = NO;
        
        [NEDNSProxyManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NEDNSProxyManager *> * _Nullable managers, NSError * _Nullable error) {
            if (!error && managers) {
                for (NEDNSProxyManager *manager in managers) {
                    NEDNSProxyProviderProtocol *protocol = (NEDNSProxyProviderProtocol *)manager.providerProtocol;
                    if (protocol && [protocol.providerBundleIdentifier isEqualToString:extensionBundleID]) {
                        installed = YES;
                        break;
                    }
                }
            }
            dispatch_semaphore_signal(checkSemaphore);
        }];
        
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
        dispatch_semaphore_wait(checkSemaphore, timeout);
        
        return installed ? 1 : 0;
    }
}