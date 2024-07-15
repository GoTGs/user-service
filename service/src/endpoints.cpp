#include "../include/endpoints.hpp"

std::variant<TokenError, json> ValidateToken(std::string& token) {
	// remove "Bearer "
	token.erase(0, 7);

	if (token.empty()) {
		return TokenError{ CppHttp::Net::ResponseType::NOT_AUTHORIZED, "Missing token" };
	}

	jwt::verifier<jwt::default_clock, jwt::traits::nlohmann_json> verifier = jwt::verify<jwt::traits::nlohmann_json>().allow_algorithm(jwt::algorithm::rs512{ "", std::getenv("RSASECRET"), "", ""}).with_issuer("auth0");
	auto decodedToken = jwt::decode<jwt::traits::nlohmann_json>(token);

	std::error_code ec;
	verifier.verify(decodedToken, ec);

	if (ec) {
		std::osyncstream(std::cout) << "\033[1;31m[-] Error: " << ec.message() << "\033[0m\n";
		return TokenError{ CppHttp::Net::ResponseType::INTERNAL_ERROR, ec.message() };
	}

	auto tokenJson = decodedToken.get_payload_json();

	return tokenJson;
}

returnType GetUser(CppHttp::Net::Request req) {
	soci::session* sql = Database::GetInstance()->GetSession();
	std::string token = req.m_info.headers["Authorization"];

	auto tokenVariant = ValidateToken(token);

	if (std::holds_alternative<TokenError>(tokenVariant)) {
		TokenError error = std::get<TokenError>(tokenVariant);
		return { error.type, error.message, {} };
	}

	json tokenJson = std::get<json>(tokenVariant);
	std::string id = tokenJson["id"];

	User user;
	*sql << "SELECT * FROM users WHERE id = :id", soci::use(id), soci::into(user);

	if (user.email.empty()) {
		return { CppHttp::Net::ResponseType::NOT_FOUND, "User not found", {} };
	}

	json response = {
		{ "id", user.id },
		{ "email", user.email },
		{ "first_name", user.firstName },
		{ "last_name", user.lastName }
	};

	return { CppHttp::Net::ResponseType::JSON, response.dump(4), {} };
}