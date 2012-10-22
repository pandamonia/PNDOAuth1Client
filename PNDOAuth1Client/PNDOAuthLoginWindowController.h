//
//  PNDOAuthLoginWindowController.h
//  PNDOAuth1Client (Mac)
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "PNDOAuth1Client.h"

@class WebView;

@interface PNDOAuthLoginWindowController : NSWindowController <PNDOAuth1LogInController, NSWindowDelegate>

- (id)init;
- (id)initWithResourceBundle: (NSBundle *)bundle;

@property (nonatomic, weak) IBOutlet WebView *webView;
@property (nonatomic, weak) IBOutlet NSSegmentedControl *navigationControl;
@property (nonatomic, weak) IBOutlet NSButton *closeButton;

- (IBAction)closeWindow:(id)sender;

// Block to handle requests sent to an external browser.
// The controller's default behavior is to use NSWorkspace's openURL:
@property (nonatomic, copy) void(^externalRequestHandler)(PNDOAuthLoginWindowController *controller, NSURLRequest *request);

@end
