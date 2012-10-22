//
//  PNDOAuth1Client.h
//  PNDOAuth1Client
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "AFHTTPClient.h"
#import "AFHTTPRequestOperation.h"
#import "PNDOAuth1Credential.h"

typedef NS_ENUM(NSInteger, PNDOAuthSignatureMethod) {
    PNDOAuthSignatureMethodPlaintext = 0,
    PNDOAuthSignatureMethodHMAC_SHA1 = 1,
};

typedef NS_ENUM(NSUInteger, PNDOAuthError) {
	PNDOAuthUnknownError = 'UNKN',
	PNDOAuthMissingPropertyError = 'PROP',
	PNDOAuthTokenFetchFailedError = 'FTCH',
	PNDOAuthCancelledError = 'CNCL',
};

extern NSString *const PNDOAuthErrorDomain;
extern NSString *const PNDOAuthErrorMissingPropertyKey;

extern NSString *const PNDOAuthTokenFetchWillStartNotification;
extern NSString *const PNDOAuthTokenFetchDidSucceedNotification;
extern NSString *const PNDOAuthTokenFetchDidFailNotification;

extern NSString *const PNDOAuthTokenFetchTypeKey;
extern NSString *const PNDOAuthTokenFetchErrorKey;

extern NSString *const PNDOAuthTokenFetchTypeRequest;
extern NSString *const PNDOAuthTokenFetchTypeAccess;
extern NSString *const PNDOAuthTokenFetchTypeUserInfo;

extern NSString *const PNDOAuthUserWillSignInNotification;
extern NSString *const PNDOAuthUserDidSignInNotification;
extern NSString *const PNDOAuthUserCancelledSigningInNotification;

extern NSString *const PNDOAuthNetworkLostNotification;
extern NSString *const PNDOAuthNetworkFoundNotification;

extern NSString *const PNDOAuthConsumerKey;
extern NSString *const PNDOAuthTokenKey;
extern NSString *const PNDOAuthCallbackKey;
extern NSString *const PNDOAuthCallbackConfirmedKey;
extern NSString *const PNDOAuthTokenSecretKey;
extern NSString *const PNDOAuthSignatureMethodKey;
extern NSString *const PNDOAuthSignatureKey;
extern NSString *const PNDOAuthTimestampKey;
extern NSString *const PNDOAuthNonceKey;
extern NSString *const PNDOAuthVerifierKey;
extern NSString *const PNDOAuthVersionKey;
extern NSString *const PNDOAuthDisplayNameKey;
extern NSString *const PNDOAuthScopeKey;
extern NSString *const PNDOAuthDomainKey;
extern NSString *const PNDOAuthHostedDomainKey;
extern NSString *const PNDOAuthIconURLKey;
extern NSString *const PNDOAuthLanguageKey;
extern NSString *const PNDOAuthMobileKey;
extern NSString *const PNDOAuthServiceProviderKey;
extern NSString *const PNDOAuthUserEmailKey;
extern NSString *const PNDOAuthUserEmailIsVerifiedKey;

@protocol PNDOAuth1LogInController <NSObject>

@property (nonatomic, copy) BOOL (^redirectHandler)(NSURLRequest *request);
@property (nonatomic, copy) void (^successHandler)(NSString *responseStr);
@property (nonatomic, copy) void (^cancelledHandler)(void);

- (void)present;
- (void)dismiss;
- (void)loadURLRequest:(NSURLRequest *)request;

@end

@interface PNDOAuth1Client : AFHTTPClient

- (id)initWithBaseURL:(NSURL *)url serviceName:(NSString *)serviceName;
- (id)initWithBaseURL:(NSURL *)url serviceName:(NSString *)serviceName username: (NSString *)username;
- (id)initWithBaseURL:(NSURL *)url serviceName:(NSString *)serviceName keychainIdentifier: (NSString *)identifier;

@property (nonatomic, copy) NSString *consumerKey;
@property (nonatomic, copy) NSString *consumerSecret;
@property (nonatomic) PNDOAuthSignatureMethod signatureMethod;

@property (nonatomic, copy) NSString *scope;
@property (nonatomic, copy) NSString *callback;
@property (nonatomic, copy) NSString *realm;
@property (nonatomic, copy) NSString *displayName;

@property (nonatomic, strong) NSURL *requestTokenURL;
@property (nonatomic, strong) NSURL *authorizationURL;
@property (nonatomic, strong) NSURL *accessTokenURL;

@property (nonatomic, readonly) NSString *keychainIdentifier;

@property (nonatomic, readonly) NSString *userEmail;
@property (nonatomic, readonly, getter = userEmailIsVerified) BOOL userEmailVerified;

@property (nonatomic, readonly) BOOL canAuthorize;

- (void)startSigningInWithController:(id <PNDOAuth1LogInController>)controller success:(void(^)(void))success failure:(void(^)(NSError *err))failure;
- (void)cancelSigningIn;

- (void)reset;

- (void)addRequestTokenHeaderToRequest:(NSMutableURLRequest *)request;
- (void)addAuthorizeTokenHeaderToRequest:(NSMutableURLRequest *)request;
- (void)addAccessTokenHeaderToRequest:(NSMutableURLRequest *)request;
- (void)addResourceTokenHeaderToRequest:(NSMutableURLRequest *)request;

// add OAuth URL params, as an alternative to adding headers
- (void)addRequestTokenParamsToRequest:(NSMutableURLRequest *)request;
- (void)addAuthorizeTokenParamsToRequest:(NSMutableURLRequest *)request;
- (void)addAccessTokenParamsToRequest:(NSMutableURLRequest *)request;
- (void)addResourceTokenParamsToRequest:(NSMutableURLRequest *)request;

- (void)setAuthenticationKeysForResponseData:(NSData *)data;
- (void)setAuthenticationKeysForResponseString:(NSString *)str;

@end