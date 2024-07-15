#include "../include/endpoints.hpp"
#include <thread>

int main(int argc, char** argv) {
	CppHttp::Net::Router router;
	CppHttp::Net::TcpListener server;
	server.CreateSocket();

	int requestCount = 0;

	auto onReceive = [&](CppHttp::Net::Request req) {
		router.Handle(req);
	};

	server.SetOnReceive(onReceive);

	router.AddRoute("GET", "/user/get", GetUser);

	server.Listen("0.0.0.0", 8001	, std::thread::hardware_concurrency());
}