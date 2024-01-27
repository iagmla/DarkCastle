#!/bin/bash

castle zanderfish3 -e msg test.enc castle_test.pk castle_hello.sk && castle zanderfish3 -d test.enc test.dec castle_test.sk castle_test.pk
