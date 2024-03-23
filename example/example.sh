#!/bin/bash

castle -e msg msg.enc hello.pk test.sk && castle -d msg.enc msg.dec test.pk hello.sk
