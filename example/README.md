# DarkTomb Example

User Test sends a message "Hello World!" to user Hello.

tomb akms-cbc -e msg msg.enc hello.pk test.sk && tomb akms-cbc -d msg.enc msg.dec test.pk hello.sk
