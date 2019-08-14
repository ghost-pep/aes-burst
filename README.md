# AES Burst

This is a tool for brute forcing AES keys. It was developed with inspiration from 
[AES Brute](https://github.com/unicornsasfuel/aesbrute)
by unicornsasfuel. It was presented to DEFCON 27 under the talk Practical Key Search Attacks Against Modern Symmetric Ciphers.

## Installation

This repo uses GNU make. The code has different dependencies depending on the program used. For the program presented at DEFCON, install cryptopp (`aesburst-multi`). Just clone the repository and then `cd aes_burst` and `make`. It's that simple!
After building, 3 programs are generated: `aesburst-simple`, `aesburst-multi`, and `aesburst-ocl`.


## Usage

`./<aesburst program name>` for the usage message.

The `test` folder is for testing the implementation and benchmarking. Feel free to run any of the bash scripts to get an example of how to run the code.

## Simple Implementation

This implementation is just to see if there is any performance increase from porting 
[AES Brute](https://github.com/unicornsasfuel/aesbrute) from Python to C++. From our testing, this
improved the performance slightly.


## Multithreaded Implementation

This implementation was the first attempt at parallelism. It uses a thread pool and allows the user 
to define the number of threads that will be used in the brute force. The threads each handle jobs
from a queue, with each job being to handle a specific key.
It saw a performance increase over the
simple implementation in certain situations, but because of the limitations of AES-NI, the ideal number of threads correlates with the AES hardware on your processor.
