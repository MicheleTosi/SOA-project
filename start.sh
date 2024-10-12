#!/bin/bash
cd singlefile-FS
make all
make load-FS-driver
make create-fs
make mount-fs
cd ..
make all
make load
