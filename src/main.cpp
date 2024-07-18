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
	router.AddRoute("GET", "/user/get/all", GetUsers);
	router.AddRoute("PUT", "/user/update", UpdateUser);
	router.AddRoute("DELETE", "/user/delete", DeleteUser);

	server.Listen("0.0.0.0", 8001, std::thread::hardware_concurrency());

	Database::GetInstance()->Close();
}