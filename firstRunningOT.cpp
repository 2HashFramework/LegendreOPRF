#include <iostream>
#include <string.h>
#include <stdio.h>
#include <numeric>

#include <libOTe/config.h>

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/SimplestOT.h>
#include "coproto/Socket/AsioSocket.h"

using namespace osuCrypto;
using namespace std;


int main(){
    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
	auto sockets = coproto::LocalAsyncSocket::makePair();

	// The code to be run by the OT receiver.
	auto recverThread = std::thread([&]() {
		PRNG prng(sysRandomSeed());
		SimplestOT recver;

		// Choose which messages should be received.
		BitVector choices(2);
		choices[0] = 0;
        choices[1] = 1;
		//...

		// Receive the messages
		std::vector<block> messages(2);
		auto proto = recver.receiveChosen(choices, messages, prng, sockets[0]);
        std::cout  << "Received 0 " << messages[0] << std::endl;
		coproto::sync_wait(proto);
        std::cout  << "Received 0 " << messages[0] << std::endl;
        std::cout  << "Received 1 " << messages[1] << std::endl;
		});

	PRNG prng(sysRandomSeed());
	SimplestOT sender;

	// Choose which messages should be sent.
	std::vector<std::array<block, 2>> sendMessages(2);
	sendMessages[0] = { toBlock(54), toBlock(33) };
	sendMessages[1] = { toBlock(54), toBlock(33) };

	// Send the messages.
	auto proto = sender.sendChosen(sendMessages, prng, sockets[1]);

	auto r = coproto::sync_wait(macoro::wrap(proto));
    cout << "Send messages " << sendMessages[0][0] << " and " << sendMessages[0][1] << endl;
    cout << "Send messages " << sendMessages[1][0] << " and " << sendMessages[1][1] << endl;

	recverThread.join();

	r.value();
}
