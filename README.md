# Legendre OPRF
This is an implementation of the Legendre Symbol-based OPRF of Beullens et al. [2Hash OPRF framework](https://eprint.iacr.org/2024/450.pdf).


The goal of the implementation is to prove the concrete efficiency of this approach. It was tested under WSL on Windows, Fedora, and under Ubuntu. However, this is not an industry-level implementation and there might still be subtle bugs.

## Structure
The implementation relies on the [libOTe](https://github.com/osu-crypto/libOTe) library for the Oblivious Transfer implementations and for the implementation of the Puncturable PRF.
 - `OPRFLeg.h` contains a class that allows the execution of the OPRF protocol. The function `eval` is what the OPRF client executes. It takes an input `x` and writes the OPRF output to `output`. The function `blindedEval` is what the OPRF server executes. It takes the key `Key` as input and has no output.
 - The folder `fe25519` contains an implementation of finite field arithmetic for the prime field modulo $2^{255}-19$. The implementation is originally based on [NaCl](https://nacl.cr.yp.to/install.html) but was adapted to our use.
 - The files `smallSetVoleFast.h`, `VolePlus.h`, `voleUtils.h`, and `LegOPRF_ZKProof.h` contain the building blocks for the OPRF.
 - The folder `tests` contains tests.
 - The files `VolePlus.GMP.h`, `smallSetVoleGMP.h`, and `MockSmallSetVole.h` exist only for testing purposes and can be ignored.

## Building
For building the code, one needs to install a c++ compiler, git (tested with version 2.48.1),libtool (tested with version 2.4.7), cmake (min. version 3.15), GMP (tested with version 6.3.0), and libOTe (tested with commit 2f68131), although our final implementation does not make use of GMP.

### Installing Preliminaries:
To install GMP and cmake on Ubuntu, you can run
`sudo apt install libgmp3-dev cmake g++ libtool git` 
or on Fedora 
`sudo dnf install gmp-devel cmake gcc-c++ libtool git`


To install libOTe, you must run the following *in the same folder* where the main file is

`git clone https://github.com/osu-crypto/libOTe.git`

`cd libOTe`

`python3 build.py --all --boost --sodium` (This might take a while)

`python3 build.py --sudo --install`

You will get prompted to enter your sudo password.
In case this does not work, more detailed instructions can be found [here](https://github.com/osu-crypto/libOTe).

### Building the OPRF
To build the OPRF, you first have to create a build directory
`mkdir build`
`cd build`
Then, you can run CMAKE
`cmake -DCMAKE_BUILD_TYPE=Release ..`
`cmake --build .`


## Testing
One can run all tests by typing 
`ctest` while in the build folder. 
`ctest -VV` gives a more verbose output.

For just running the OPRF one can run
`ctest -R OPRFleg -VV`.
