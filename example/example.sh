#!/bin/bash

castle qapla -e msg test.enc castle_test.pk castle_hello.sk && castle qapla -d test.enc test.dec castle_test.sk castle_test.pk
