#!/bin/bash
cd singlefile-FS
make clean
make remove
cd ../user
make clean
cd ..
make unload
make clean
