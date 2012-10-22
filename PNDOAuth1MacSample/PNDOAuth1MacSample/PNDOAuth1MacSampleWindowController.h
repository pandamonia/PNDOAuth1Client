//
//  PNDOAuth1MacSampleWindowController.h
//  PNDOAuth1Client Mac Sample
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

@interface PNDOAuth1MacSampleWindowController : NSWindowController

@property (nonatomic, weak) IBOutlet NSButton *signInOutButton;
@property (nonatomic, weak) IBOutlet NSTextField *usernameField;
@property (nonatomic, weak) IBOutlet NSTextField *tokenField;
@property (nonatomic, weak) IBOutlet NSProgressIndicator *spinner;

@end
