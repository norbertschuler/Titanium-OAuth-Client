/*
 * Xing OAuth Client
 * Copyright 2012, Norbert Schuler, epublica GmbH
 * based upon:
 *
 * Titanium OAuth Client
 *
 * Copyright 2010, Social Vitamin, Inc.
 * Licensed under the MIT
 * Copyright (c) 2010 Social Vitamin, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

Ti.include('sha1.js');
Ti.include('oauth.js');

var XingOAuth = function(ck, cs) {

	var self = this;
	var currentWin = Ti.UI.currentWindow;
	var authWebView = null;
	var oauthWin = null;

	var consumer = {
		consumerKey : ck,
		consumerSecret : cs,
		serviceProvider : {
			signatureMethod : 'HMAC-SHA1',
			requestTokenURL : 'https://api.xing.com/v1/request_token',
			userAuthorizationURL : 'https://api.xing.com/v1/authorize',
			accessTokenURL : 'https://api.xing.com/v1/access_token',
			oauthVersion : '1.0'
		}
	};

	var accessor = {
		consumerSecret : consumer.consumerSecret,
		tokenSecret : ''
	};

	// Get Authorization PIN
	var getPIN = function(callback) {
		var html = authWebView.evalJS("document.getElementById('verifier').innerHTML");
		if(html != '') {
			var regex = new RegExp("([0-9]+)", "m");
			if(regex) {
				var pin = html.match(regex)[0];
				if(pin) {
					Ti.API.debug("Pin found: " + pin);
					self.accessToken(pin, callback);
					if(oauthWin != null) {
						oauthWin.close();
					}
				}
			}
		}
	};
	// Show Authorization Web View
	this.oauthWebView = function(params, callback) {

		var win = Ti.UI.createWindow({
			title : 'Xing',
			navBarHidden : true,
		});

		// WebView
		authWebView = Ti.UI.createWebView({
			url : params.url
		});
		authWebView.addEventListener('load', function() {
			return getPIN(callback);
		});
		win.add(authWebView);

		// Remove window button
		var cl = Ti.UI.createLabel({
			width : 24,
			height : 24,
			right : 10,
			top : 10,
			borderRadius : 6,
			borderColor : '#0E5657',
			backgroundColor : '#0E5657',
			text : 'X',
			textAlign : 'center',
			font : {
				fontSize : 11,
				fontWeight : 'bold'
			},
			color : '#FFF'
		});
		cl.addEventListener('click', function(e) {
			callback({ success : false });
			win.close();
		});
		win.add(cl);

		win.open({ modal : true });
		oauthWin = win;
	};
	// Logged in?
	this.loggedIn = function() {
		return (Ti.App.Properties.getString('accessTokenXing') == null && Ti.App.Properties.getString('accessTokenXingSecret') == null) ? false : true;
	};
	// Request Token
	this.requestToken = function(callback) {

		if(Ti.App.Properties.getString('accessTokenXing') != null && Ti.App.Properties.getString('accessTokenXingSecret') != null) {
			// Login
			callback({ success : true });
			self.dispatch('login');
			return;
		}

		var message = {
			method : 'POST',
			action : consumer.serviceProvider.requestTokenURL,
			parameters : [
				['oauth_signature_method', consumer.serviceProvider.signatureMethod],
				['oauth_consumer_key', consumer.consumerKey],
				['oauth_version', consumer.serviceProvider.oauthVersion],
				['oauth_callback', 'oob'],
			]
		};

		accessor.tokenSecret = ''; // empty accessor for signature

		OAuth.setTimestampAndNonce(message);
		OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
		OAuth.SignatureMethod.sign(message, accessor);

		var finalUrl = OAuth.addToURL(message.action, message.parameters);
		Ti.API.debug("requestToken = " + finalUrl);

		var xhr = Titanium.Network.createHTTPClient();
		xhr.onload = function() {
			Ti.API.debug("requestToken response = " + this.responseText);

			if(!this.responseText.match(/oauth_token=([^&]+)&/)) {
				callback({ success : false });
				self.logout();
			}

			// Set Tokens
			Ti.App.Properties.setString('oauthTokenXing', this.responseText.match(/oauth_token=([^&]+)/)[1]);
			Ti.App.Properties.setString('oauthTokenXingSecret', this.responseText.match(/oauth_token_secret=([^&]+)/)[1]);

			// Access Token Secret
			accessor.tokenSecret = Ti.App.Properties.getString('accessTokenXingSecret');

			// Verify if we have an access token if we dont show auth webview
			if(Ti.App.Properties.getString('accessTokenXing') == null && Ti.App.Properties.getString('accessTokenXingSecret') == null) {
				self.oauthWebView({
					url : consumer.serviceProvider.userAuthorizationURL + '?' + this.responseText
				}, callback);
			} else {
				callback({ success : true });
			}

		};
		xhr.onerror = function(e) {
			Ti.API.debug("requestToken response = " + this.responseText);

			Ti.UI.createAlertDialog({
				title : 'Service Unavailable',
				message : 'Service unavailable please try again later.'
			}).show();

			// Logout
			callback({ success : false });
			self.logout();
		};
		xhr.open('POST', finalUrl);
		xhr.send();

	};
	// Access Token
	this.accessToken = function(pin, callback) {

		var message = {
			method : 'POST',
			action : consumer.serviceProvider.accessTokenURL,
			parameters : [
				['oauth_signature_method', consumer.serviceProvider.signatureMethod],
				['oauth_consumer_key', consumer.consumerKey],
				['oauth_version', consumer.serviceProvider.oauthVersion],
				['oauth_token', Ti.App.Properties.getString('oauthTokenXing')],
				['oauth_verifier', pin]
			]
		};

		accessor.tokenSecret = Ti.App.Properties.getString('oauthTokenXingSecret');

		OAuth.setTimestampAndNonce(message);
		OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
		OAuth.SignatureMethod.sign(message, accessor);

		var finalUrl = OAuth.addToURL(message.action, message.parameters);
		Ti.API.debug("accessToken = " + finalUrl);

		var xhr = Titanium.Network.createHTTPClient();
		xhr.onload = function() {
			Ti.API.debug("accessToken response = " + this.responseText);

			if(!this.responseText.match(/oauth_token=([^&]+)&/)) {
				callback({ success : false });
				self.logout();
			}

			Ti.App.Properties.setString('accessTokenXing', this.responseText.match(/oauth_token=([^&]+)&/)[1]);
			Ti.App.Properties.setString('accessTokenXingSecret', this.responseText.match(/oauth_token_secret=([^&]+)&/)[1]);
			Ti.App.Properties.setString('xing_user_id', this.responseText.match(/user_id=([^&]+)/)[1]);
			Ti.API.debug("found user id = " + Ti.App.Properties.getString('xing_user_id'));

			// Login
			callback({ success : true });
			self.dispatch('login');
		};
		xhr.onerror = function(e) {
			Ti.API.debug("accessToken response = " + this.responseText);

			Ti.UI.createAlertDialog({
				title : 'Service Unavailable',
				message : 'Service unavailable please try again later.'
			}).show();

			// Logout
			callback({ success : false });
			self.logout();
		};
		xhr.open('POST', finalUrl);
		xhr.send();

	};
	// Request
	this.request = function(options, callback) {

		var message = {
			method : options.method,
			action : options.action,
			parameters : [
				['oauth_signature_method', consumer.serviceProvider.signatureMethod],
				['oauth_consumer_key', consumer.consumerKey],
				['oauth_version', consumer.serviceProvider.oauthVersion],
				['oauth_token', Ti.App.Properties.getString('accessTokenXing')]
			]
		};

		for(param in options.parameters) {
			message.parameters.push(options.parameters[param]);
		};

		// Access Token Secret
		accessor.tokenSecret = Ti.App.Properties.getString('accessTokenXingSecret');

		OAuth.setTimestampAndNonce(message);
		OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
		OAuth.SignatureMethod.sign(message, accessor);

		var finalUrl = OAuth.addToURL(message.action, message.parameters);
		Ti.API.debug("request = " + finalUrl);

		var xhr = Titanium.Network.createHTTPClient({
			timeout : 200000
		});
		xhr.onload = function() {
			Ti.API.debug("request response = " + this.responseText);

			callback(this.responseText);
		};
		xhr.onerror = function(e) {
			Ti.API.debug("request response = " + this.responseText);

			Ti.UI.createAlertDialog({
				title : 'Service Unavailable',
				message : 'An error ocurred while making a request.'
			}).show();

			// Logout
			self.dispatch('logout');
		};
		xhr.open(options.method, finalUrl, false);
		xhr.send();

	};

	this.logout = function() {
		Ti.App.Properties.setString('oauthTokenXing', null);
		Ti.App.Properties.setString('oauthTokenXingSecret', null);
		Ti.App.Properties.setString('accessTokenXing', null);
		Ti.App.Properties.setString('accessTokenXingSecret', null);
		Ti.App.Properties.setString('xing_user_id', null);

		// Logout
		self.dispatch('logout');
	};
};
// XingDispatcher
function XingDispatcher() {
	this.events = [];
};

XingDispatcher.prototype.addEventListener = function(event, callback) {
	this.events[event] = this.events[event] || [];
	if(this.events[event]) {
		this.events[event].push(callback);
	}
};

XingDispatcher.prototype.removeEventListener = function(event, callback) {
	if(this.events[event]) {
		var listeners = this.events[event];
		for(var i = listeners.length - 1; i >= 0; --i) {
			if(listeners[i] === callback) {
				listeners.splice(i, 1);
				return true;
			}
		}
	}
	return false;
};

XingDispatcher.prototype.dispatch = function(event) {
	if(this.events[event]) {
		var listeners = this.events[event], len = listeners.length;
		while(len--) {
			listeners[len](this);
		}
	}
};

XingOAuth.prototype = new XingDispatcher();
