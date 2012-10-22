//
//  PNDOAuthLoginWindowController.m
//  PNDOAuth1Client (Mac)
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "PNDOAuthLoginWindowController.h"
#import <WebKit/WebKit.h>

@interface PNDOAuthLoginWindowController () {
	BOOL _hasCalledFinished;
	BOOL _hasDoneFinalRedirect;
	NSModalSession _modalSession;
}

@end

@implementation PNDOAuthLoginWindowController

@synthesize successHandler = _successHandler, cancelledHandler = _cancelledHandler, redirectHandler = _redirectHandler;

- (id)init
{
	return [self initWithResourceBundle: nil];
}

- (id)initWithResourceBundle: (NSBundle *)bundle
{
	NSString *nibPath = [bundle ?: [NSBundle mainBundle] pathForResource: NSStringFromClass([self class]) ofType:@"nib"];
	return [super initWithWindowNibPath:nibPath owner:self];
}

- (void)windowDidLoad
{
    [super windowDidLoad];
    
	[self.webView addObserver: self forKeyPath: @"canGoBack" options: NSKeyValueObservingOptionNew context: NULL];
	[self.webView addObserver: self forKeyPath: @"canGoForward" options: NSKeyValueObservingOptionNew context: NULL];
}


- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context {
	if ([keyPath isEqualToString: @"canGoBack"] || [keyPath isEqualToString: @"canGoForward"]) {
		[self.navigationControl setEnabled: [change[NSKeyValueChangeNewKey] boolValue] forSegment: [keyPath isEqualToString: @"canGoBack"] ? 0 : 1];
		return;
	}
	[super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
}

#pragma mark - Actions

- (IBAction)navigationButtonClicked:(NSSegmentedControl *)sender {
	if (sender.selectedSegment == 0) {
		[self.webView goBack: sender];
	} else {
		[self.webView goForward: sender];
	}
}

- (IBAction)closeWindow:(id)sender {
	[self dismiss];
	[self handlePrematureWindowClose];
}

- (void)handlePrematureWindowClose {
	if (!_hasDoneFinalRedirect) {
		if (self.cancelledHandler) self.cancelledHandler();
		_hasDoneFinalRedirect = YES;
	}
}

#pragma mark -

- (void)present {
	_modalSession = [NSApp beginModalSessionForWindow: [self window]];
}

- (void)dismiss {
	[NSApp endModalSession: _modalSession];
	[self.window close];
}

- (void)loadURLRequest:(NSURLRequest *)request {
	if (!request) {
		[self dismiss];
		return;
	}

	const NSTimeInterval kJanuary2011 = 1293840000;
	BOOL isDateValid = ([[NSDate date] timeIntervalSince1970] > kJanuary2011);
	if (isDateValid) {
		// start the asynchronous load of the sign-in web page
		[self.webView.mainFrame performSelector:@selector(loadRequest:) withObject: request afterDelay:0.01 inModes:@[NSRunLoopCommonModes]];
	} else {
		// clock date is invalid, so signing in would fail with an unhelpful error
		// from the server. Warn the user in an html string showing a watch icon,
		// question mark, and the system date and time. Hopefully this will clue
		// in brighter users, or at least let them make a useful screenshot to show
		// to developers.
		//
		// Even better is for apps to check the system clock and show some more
		// helpful, localized instructions for users; this is really a fallback.
		NSString *htmlTemplate = @"<html><body><div align=center><font size='7'>"
		"&#x231A; ?<br><i>System Clock Incorrect</i><br>%@"
		"</font></div></body></html>";
		NSString *errHTML = [NSString stringWithFormat:htmlTemplate, [NSDate date]];

		[self.webView.mainFrame loadHTMLString:errHTML baseURL:nil];
	}	
}

#pragma mark WebView delegate

- (NSURLRequest *)webView:(WebView *)sender resource:(id)identifier willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse fromDataSource:(WebDataSource *)dataSource {
	// override WebKit's cookie storage with our own to avoid cookie persistence
	// across sign-ins and interaction with the Safari browser's sign-in state
	[self handleCookiesForResponse:redirectResponse];
	request = [self addCookiesToRequest:request];

	if (!_hasDoneFinalRedirect) {
		_hasDoneFinalRedirect = self.redirectHandler(request);
		if (_hasDoneFinalRedirect) {
			if (self.successHandler)
				self.successHandler(request.URL.query);

			[self dismiss];
			return nil;
		}
	}
	return request;
}


- (void)webView:(WebView *)sender resource:(id)identifier didReceiveResponse:(NSURLResponse *)response fromDataSource:(WebDataSource *)dataSource {
	// override WebKit's cookie storage with our own
	[self handleCookiesForResponse:response];
}

- (void)windowWillClose:(NSNotification *)note {
	[self handlePrematureWindowClose];
}

- (void)webView:(WebView *)webView decidePolicyForNewWindowAction:(NSDictionary *)actionInformation request:(NSURLRequest *)request newFrameName:(NSString *)frameName decisionListener:(id<WebPolicyDecisionListener>)listener {
	if (self.externalRequestHandler) {
		self.externalRequestHandler(self, request);
	} else {
		// default behavior is to open the URL in NSWorkspace's default browser
		NSURL *url = [request URL];
		[[NSWorkspace sharedWorkspace] openURL:url];
	}
	[listener ignore];
}

#pragma mark Cookie management

// Rather than let the WebView use Safari's default cookie storage, we intercept
// requests and response to segregate and later discard cookies from signing in.
//
// This allows the application to actually sign out by discarding the auth token
// rather than the user being kept signed in by the cookies.

- (void)handleCookiesForResponse:(NSURLResponse *)response {
	#warning TODO - Cookies!
	/*if ([response respondsToSelector:@selector(allHeaderFields)]) {
		// grab the cookies from the header as NSHTTPCookies and store them locally
		NSDictionary *headers = [(NSHTTPURLResponse *)response allHeaderFields];
		if (headers) {
			NSURL *url = [response URL];
			NSArray *cookies = [NSHTTPCookie cookiesWithResponseHeaderFields:headers
																	  forURL:url];
			if ([cookies count] > 0) {
				self.cookieStorage.cookies = cookies;
			}
		}
	}*/
}

- (NSURLRequest *)addCookiesToRequest:(NSURLRequest *)request {
	#warning TODO - Cookies!
	// override WebKit's usual automatic storage of cookies
	NSMutableURLRequest *mutableRequest = [request mutableCopy];
	[mutableRequest setHTTPShouldHandleCookies:NO];

	// add our locally-stored cookies for this URL, if any
	/*NSArray *cookies = [self.cookieStorage cookiesForURL: request.URL];
	if (cookies.count) {
		NSDictionary *headers = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
		NSString *cookieHeader = headers[@"Cookie"];
		if (cookieHeader) {
			[mutableRequest setValue:cookieHeader forHTTPHeaderField:@"Cookie"];
		}
	}*/
	
	return mutableRequest;
}

@end
