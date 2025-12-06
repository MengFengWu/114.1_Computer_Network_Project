all:
	rm -rf ../bin
	mkdir ../bin
	g++ -std=c++17 -pthread server.cpp crypto.cpp -o ../bin/server -lssl -lcrypto
	g++ -std=c++17 -pthread client.cpp crypto.cpp -o ../bin/client -lssl -lcrypto
clean:
	rm -rf ../bin