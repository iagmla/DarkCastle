#!/bin/bash

castle zanderfish3 -e msg msg.enc hello.pk test.sk && castle zanderfish3 -d msg.enc msg.dec test.pk hello.sk
