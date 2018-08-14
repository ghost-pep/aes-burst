# AES Burst

This is a tool for brute forcing AES keys. It was developed with inspiration from 
[AES Brute](https://github.com/unicornsasfuel/aesbrute)
by unicornsasfuel.

## Installation

This repo uses GNU make. Just clone the repository and then `cd aes_burst` and `make`. It's that simple!
After building, 3 programs are generated: `aesburst-simple`, `aesburst-multi`, and `aesburst-ocl`.


## Usage

`./<aesburst program name>` for the usage message.

The `test` folder is for testing the implementation and benchmarking. Feel free to run any of the bash scripts.

## Simple Implementation

This implementation is just to see if there is any performance increase from porting 
[AES Brute](https://github.com/unicornsasfuel/aesbrute) from Python to C++. From our testing, this
improved the performance slightly.


## Multithreaded Implementation

This implementation was the first attempt at parallelism. It uses a thread pool and allows the user 
to define the number of threads that will be used in the brute force. The threads each handle jobs
from a queue, with each job being to handle a specific key.
It saw a performance increase over the
simple implementation in certain situations, but starting up 20 threads for 1000 keys and one sample
has a massive performance decrease becasue of the overhead of creating the thread pool.

## OpenCL Implementation

This implementation is not complete. It attempts to target powerful password cracking rigs. Help is 
definitely wanted so feel free to make a pull request!
