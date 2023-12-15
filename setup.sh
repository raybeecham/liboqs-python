cmake -S liboqs-0.9.0 -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 8
cmake --build liboqs/build --target install
sudo export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
. venv/bin/activate
