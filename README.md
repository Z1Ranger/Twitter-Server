# Twitter-Server
A simple version of Twitter server

### Working Description
When a new user connects, the server will send them "Welcome to CSC209 Twitter! Enter your username: ". After they input an acceptable name that is not equal to any existing users's username and is not the empty string, they are added to Twitter, and all active users (if any) are alerted to the addition. If they input an unacceptable name, they will be notified and asked again to enter their name.

With my server, users can join or leave Twitter at any time. A user leaves by issuing the quit command or exiting/killing nc.

The 4 functional commands are:
**follow**,
**unfollow**,
**send -message-**, 
**show**,

If a user issues an invalid command or enters a blank line, they will be informed of "Invalid command".

### User Interaction
[Example](https://github.com/Z1Ranger/Twitter-Server/tree/master/Example%20Interaction) 
