FROM ubuntu:24.04

RUN apt-get update \
    && \
    apt-get install -y \
        libgmp3-dev cmake g++ libtool git \
        python3 sudo

WORKDIR /home/
RUN git clone https://github.com/2HashFramework/LegendreOPRF 
RUN git clone https://github.com/osu-crypto/libOTe /home/LegendreOPRF/libOTe
WORKDIR /home/LegendreOPRF/libOTe
RUN python3 build.py --all --boost --sodium
RUN python3 build.py --sudo --install
WORKDIR /home/LegendreOPRF
RUN mkdir build
WORKDIR /home/LegendreOPRF/build
RUN cmake -DCMAKE_BUILD_TYPE=Release ..
RUN cmake --build .

SHELL ["/bin/bash", "-c"]