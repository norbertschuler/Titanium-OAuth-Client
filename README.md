Titanium OAuth Client
================================

What I changed?
---------------------------------------
I just added three more files implementing an Oauth Client for XING and Linkedin and a changed Twitter Client. I used this for implementing my quiz app you can find in Google Play: https://play.google.com/store/apps/details?id=com.epublica.contactquiz .

Example:

	Ti.include('js/xing_oauth.js');

	var xing_oauth = new XingOAuth('Consumer key','Consumer secret');

	xing_oauth.requestToken(function(e) {
		if (!e.success) {
			alert('request failed');
			return;
		}
		xing_oauth.request({ method : 'GET', action : 'https://api.xing.com/v1/users/me/contacts.json?user_fields=id,display_name', parameters : [] }, function(data) {
			var response = JSON.parse(data);
			var users = response.contacts.users;
			var total = response.contacts.total;
		}
	});

What is it?
---------------------------------------
This is a very simple and user friendly OAuth Client for Titanium Mobile. I'm currently using it for Twitter.
 

How do I use it?
---------------------------------------
Example:

	Ti.include('js/titanium_oauth.js');
	
	var oauth = new TitaniumOAuth('Consumer key','Consumer secret');
	
	var options = {
		        method: 'POST',
		        action: 'https://api.twitter.com/1/statuses/update.json',
		        parameters: [
		           ['status', 'Just installed an App for the iPhone.']
		       ]
		    };
	
	oauth.requestToken(function() {
		oauth.request(options, function(data) {
			Ti.API.info(data);
		});
	});


Login and Logout Events

    oauth.addEventListener('login', function(){ 
	    // Do something
    });

    oauth.addEventListener('logout', function(){ 
	    // Do something
    });
    
Checking if you are logged in.

    if (oauth.loggedIn()) { 
    	// Do something
    };
	
Login Out

    oauth.logout();
    






