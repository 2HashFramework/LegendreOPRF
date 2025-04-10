# Legendre OPRF
This is an implementation of the Legendre Symbol-based OPRF of Beullens et al. [2Hash OPRF framework](https://eprint.iacr.org/2024/450.pdf).


The goal of the implementation is to prove the concrete efficiency of this approach. It was tested under WSL on Windows, Fedora, and under Ubuntu. However, this is not an industry-level implementation and there might still be subtle bugs.

## Structure
The implementation relies on the [libOTe](https://github.com/osu-crypto/libOTe) library for the Oblivious Transfer implementations and for the implementation of the Puncturable PRF.
 - `OPRFLeg.h` contains a class that allows the execution of the OPRF protocol. The function `eval` is what the OPRF client executes. It takes an input `x` and writes the OPRF output to `output`. The function `blindedEval` is what the OPRF server executes. It takes the key `Key` as input and has no output.
 - The folder `fe25519` contains an implementation of finite field arithmetic for the prime field modulo $2^{255}-19$. The implementation is originally based on [NaCl](https://nacl.cr.yp.to/install.html) but was adapted to our use.
 - The files `smallSetVoleFast.h`, `VolePlus.h`, `voleUtils.h`, and `LegOPRF_ZKProof.h` contain the building blocks for the OPRF.
    - `smallSetVoleFast.h` contains the small-set VOLE from the [FAEST paper](https://eprint.iacr.org/2023/996.pdf).
    - `VolePlus.h` contains the VOLE+ protocol from Section E of [our paper](https://eprint.iacr.org/2024/450.pdf).
    - `voleUtils.h` contains helper functions needed for the VOLE+.
    - `LegOPRF_ZKProof.h` contains the implementation of [Quicksilver](https://eprint.iacr.org/2021/076.pdf).
 - The folder `tests` contains tests.
 - The files `VolePlus.GMP.h`, `smallSetVoleGMP.h`, and `MockSmallSetVole.h` exist only for testing purposes and can be ignored.

## Running the Code:
There is two options for running the code. 
- Manually installing the preliminaries and running the code natively. 
- Using the provided Docker image that already has everything preinstalled.

### Using Docker:
If there is a working version of [Docker installed](https://docs.docker.com/engine/install/), one can start the container by running
`docker run --rm -it sebastianfaller/legendreoprf`. 

### Installing Preliminaries Manually:
For building the code, one needs to install a c++ compiler, git (tested with version 2.48.1),libtool (tested with version 2.4.7), cmake (min. version 3.15), GMP (tested with version 6.3.0), and libOTe (tested with commit 2f68131), although our final implementation does not make use of GMP.

To install GMP and cmake on Ubuntu, you can run
`sudo apt install libgmp3-dev cmake g++ libtool git` 
or on Fedora 
`sudo dnf install gmp-devel cmake gcc-c++ libtool git`


To install libOTe, you must run the following *in the same folder* where the main file is

`git clone https://github.com/osu-crypto/libOTe.git`

`cd libOTe`

`python3 build.py --all --boost --sodium` (This might take a while)
> Troubleshooting: When errors connected to Position Independent Executables (PIE) occur here, you can try to add `set(CMAKE_POSITION_INDEPENDENT_CODE ON)` to the CMakeLists.txt of LibOTe.

`python3 build.py --sudo --install`

You will get prompted to enter your sudo password.
In case this does not work, more detailed instructions can be found [here](https://github.com/osu-crypto/libOTe).

#### Building the OPRF
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

For just running the final OPRF test that yields the running times reported in the paper, one can run
`ctest -R OPRFLeg -VV`.

## Results
We ran the above tests on a machine with an intel i9-10885H CPU, with a clock speed fixed at 2.4 GHz for three different choices of `t`.
The resulting running times are as follows:
| t    | Running Time [ms] |
| -------- | ------- |
| 6  | 178    |
| 8 | 185     |
| 10    | 313    |

