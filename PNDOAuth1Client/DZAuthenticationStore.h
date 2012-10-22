//
//  DZAuthenticationStore.h
//  PNDOAuth1Client
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

@class DZAuthenticationStore;

@protocol DZAuthenticationStore <NSObject, NSCoding, NSMutableCopying, NSCopying>

@property (nonatomic, copy, readonly) NSString *username;
@property (nonatomic, copy, readonly) id <NSObject, NSCoding> contents;
@property (nonatomic, copy, readonly) NSDictionary *userInfo;
@property (nonatomic, strong, readonly) NSDictionary *transientProperties;

- (id)initWithAuthenticationStore:(DZAuthenticationStore *)store;

- (Class)mutableClass;

@end

@protocol DZMutableAuthenticationStore <NSObject, DZAuthenticationStore>

@property (nonatomic, copy, readwrite) NSString *username;
@property (nonatomic, copy, readwrite) id <NSObject, NSCoding> contents;
@property (nonatomic, copy, readwrite) NSDictionary *userInfo;
@property (nonatomic, strong, readwrite) NSMutableDictionary *transientProperties;

@end

@interface DZAuthenticationStore : NSObject <DZAuthenticationStore>

+ (id)storeWithServiceName:(NSString *)name username:(NSString *)username contents:(id <NSObject, NSCoding>)contents userInfo:(NSDictionary *)userInfo;

@property (nonatomic, copy, readonly) NSString *serviceName;
@property (nonatomic, copy, readonly) NSString *identifier;

- (id)initWithServiceName:(NSString *)service;
- (id)initWithServiceName:(NSString *)serviceName identifier:(NSString *)identifier;

- (void)evict;

@end

@interface DZMutableAuthenticationStore : DZAuthenticationStore <DZMutableAuthenticationStore>

@end

@interface DZAuthenticationStore (DZAuthenticationStoreFactory)

+ (NSSet *)findStoresForService:(NSString *)service;
+ (instancetype)findStoreForServiceName:(NSString *)serviceName username:(NSString *)username;
+ (instancetype)findStoreForServiceName:(NSString *)serviceName identifier:(NSString *)unique;

@end