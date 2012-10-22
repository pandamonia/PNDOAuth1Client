//
//  PNDOAuth1Credential.h
//  PNDOAuth1Client
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "DZAuthenticationStore.h"

@interface PNDOAuth1Credential : DZAuthenticationStore

@property (nonatomic, copy, readonly) NSString *token;
@property (nonatomic, copy, readonly) NSString *secret;
@property (nonatomic, copy, readonly) NSString *verifier;
@property (nonatomic, copy, readonly) NSString *callbackConfirmed;
@property (nonatomic, copy, readonly) NSString *userEmailIsVerified;

@property (nonatomic, copy, readonly) NSString *domain;
@property (nonatomic, copy, readonly) NSString *hostedDomain;
@property (nonatomic, copy, readonly) NSString *iconURLString;
@property (nonatomic, copy, readonly) NSString *language;
@property (nonatomic, copy, readonly) NSString *mobile;

@property (nonatomic, readonly) BOOL hasToken;

+ (id)storeWithServiceName:(NSString *)name username:(NSString *)username responseObject:(id)data;

@end

@interface PNDMutableOAuth1Credential : PNDOAuth1Credential <DZMutableAuthenticationStore>

@property (nonatomic, copy, readwrite) NSString *token;
@property (nonatomic, copy, readwrite) NSString *secret;
@property (nonatomic, copy, readwrite) NSString *verifier;
@property (nonatomic, copy, readwrite) NSString *callbackConfirmed;
@property (nonatomic, copy, readwrite) NSString *userEmailIsVerified;

@property (nonatomic, copy, readwrite) NSString *domain;
@property (nonatomic, copy, readwrite) NSString *hostedDomain;
@property (nonatomic, copy, readwrite) NSString *iconURLString;
@property (nonatomic, copy, readwrite) NSString *language;
@property (nonatomic, copy, readwrite) NSString *mobile;
@property (nonatomic, copy, readwrite) NSString *accessToken;

@end