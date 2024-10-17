#!/bin/bash
cd singlefile-FS
make all
make load-FS-driver
make create-fs
make mount-fs
cd ../user
make all
cd ../tests
make all
cd ..
make all
make load
