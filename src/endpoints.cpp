#include "../include/endpoints.hpp"

std::variant<TokenError, json> ValidateToken(std::string& token) {
	// remove "Bearer "
	token.erase(0, 7);

	if (token.empty()) {
		return TokenError{ CppHttp::Net::ResponseType::NOT_AUTHORIZED, "Missing token" };
	}

	std::string rsaSecret = std::getenv("RSASECRET");

	size_t pos = 0;

	while ((pos = rsaSecret.find("\\n", pos)) != std::string::npos) {
		rsaSecret.replace(pos, 2, "\n");
	}

	jwt::verifier<jwt::default_clock, jwt::traits::nlohmann_json> verifier = jwt::verify<jwt::traits::nlohmann_json>().allow_algorithm(jwt::algorithm::rs512{ "", rsaSecret, "", ""}).with_issuer("auth0");
	auto decodedToken = jwt::decode<jwt::traits::nlohmann_json>(token);

	std::error_code ec;
	verifier.verify(decodedToken, ec);

	if (ec) {
		std::osyncstream(std::cout) << "\033[1;31m[-] Error: " << ec.message() << "\033[0m\n";
		return TokenError{ CppHttp::Net::ResponseType::NOT_AUTHORIZED, ec.message() };
	}

	auto tokenJson = decodedToken.get_payload_json();

	return tokenJson;
}

returnType GetUsers(CppHttp::Net::Request req) {
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
	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "SELECT * FROM users WHERE id=:id", soci::use(id), soci::into(user);
	}

	if (user.email.empty()) {
		return { CppHttp::Net::ResponseType::NOT_FOUND, "User not found", {} };
	}

	std::transform(user.role.begin(), user.role.end(), user.role.begin(), ::toupper);

	if (user.role != "ADMIN") {
		return { CppHttp::Net::ResponseType::FORBIDDEN, "You do not have permission to access this resource", {} };
	}

	std::vector<User> users;
	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		soci::rowset<User> rs = (sql->prepare << "SELECT * FROM users");
		std::move(rs.begin(), rs.end(), std::back_inserter(users));
	}

	json response = json::array();
	for (auto& u : users) {
		json user = {
			{ "id", u.id },
			{ "email", u.email },
			{ "first_name", u.firstName },
			{ "last_name", u.lastName },
			{ "role", u.role }
		};

		response.push_back(user);
	}

	return { CppHttp::Net::ResponseType::JSON, response.dump(4), {} };
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
	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "SELECT * FROM users WHERE id = :id", soci::use(id), soci::into(user);
	}
	
	if (user.email.empty()) {
		return { CppHttp::Net::ResponseType::NOT_FOUND, "User not found", {} };
	}

	json response = {
		{ "id", user.id },
		{ "email", user.email },
		{ "first_name", user.firstName },
		{ "last_name", user.lastName },
		{ "role", user.role }
	};

	return { CppHttp::Net::ResponseType::JSON, response.dump(4), {} };
}

returnType UpdateUser(CppHttp::Net::Request req) {
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
	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "SELECT * FROM users WHERE id = :id", soci::use(id), soci::into(user);
	}

	if (user.email.empty()) {
		return { CppHttp::Net::ResponseType::NOT_FOUND, "User not found", {} };
	}

	json body;

	try {
		body = json::parse(req.m_info.body);
	}
	catch (json::parse_error& e) {
		return { CppHttp::Net::ResponseType::BAD_REQUEST, e.what(), {} };
	}

	if (body.contains("email")) {
		std::string email = body["email"];

		if (email.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.") != std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Invalid email", {} };
		}

		if (email.find_first_of("@") == std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Invalid email", {} };
		}

		if (email.find_first_of(".") == std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Invalid email", {} };
		}

		user.email = email;
	}
	if (body.contains("first_name")) {
		user.firstName = body["first_name"];
	}
	if (body.contains("last_name")) {
		user.lastName = body["last_name"];
	}
	if (body.contains("password")) {
		std::string password = body["password"];

		if (password.length() < 8) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Password must be at least 8 characters", {} };
		}

		if (password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%^&*") != std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Password must only contain alphanumeric characters", {} };
		}

		user.password = Hash(password + user.salt);
	}

	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "UPDATE users SET email = :email, first_name = :first_name, last_name = :last_name, password = :password WHERE id = :id", soci::use(user.email), soci::use(user.firstName), soci::use(user.lastName), soci::use(user.password), soci::use(user.id);
	}

	json response = {
		{ "id", user.id },
		{ "email", user.email },
		{ "first_name", user.firstName },
		{ "last_name", user.lastName },
		{ "role", user.role }
	};

	return { CppHttp::Net::ResponseType::JSON, response.dump(4), {} };
}

returnType AdminUpdateUser(CppHttp::Net::Request req) {
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
	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "SELECT * FROM users WHERE id = :id", soci::use(id), soci::into(user);
	}

	if (user.email.empty()) {
		return { CppHttp::Net::ResponseType::NOT_FOUND, "User not found", {} };
	}

	std::transform(user.role.begin(), user.role.end(), user.role.begin(), ::toupper);

	if (user.role != "ADMIN") {
		return { CppHttp::Net::ResponseType::FORBIDDEN, "You do not have permission to access this resource", {} };
	}

	*sql << "SELECT * FROM users WHERE id = :id", soci::use(req.m_info.parameters["id"]), soci::into(user);

	if (user.email.empty()) {
		return { CppHttp::Net::ResponseType::NOT_FOUND, "User not found", {} };
	}

	json body;
	try {
		body = json::parse(req.m_info.body);
	}
	catch (json::parse_error& e) {
		return { CppHttp::Net::ResponseType::BAD_REQUEST, e.what(), {} };
	}

	if (body.contains("email")) {
		std::string email = body["email"];

		if (email.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.") != std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Invalid email", {} };
		}

		if (email.find_first_of("@") == std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Invalid email", {} };
		}

		if (email.find_first_of(".") == std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Invalid email", {} };
		}

		user.email = email;
	}
	if (body.contains("first_name")) {
		user.firstName = body["first_name"];
	}
	if (body.contains("last_name")) {
		user.lastName = body["last_name"];
	}
	if (body.contains("password")) {
		std::string password = body["password"];

		if (password.length() < 8) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Password must be at least 8 characters", {} };
		}

		if (password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%^&*") != std::string::npos) {
			return { CppHttp::Net::ResponseType::BAD_REQUEST, "Password must only contain alphanumeric characters", {} };
		}

		user.password = Hash(password + user.salt);
	}
	if (body.contains("role")) {
		user.role = body["role"];
	}

	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "UPDATE users SET email = :email, first_name = :first_name, last_name = :last_name, password = :password, role = :role WHERE id = :id", soci::use(user.email), soci::use(user.firstName), soci::use(user.lastName), soci::use(user.password), soci::use(user.role), soci::use(req.m_info.parameters["id"]);
	}

	json response = {
		{ "id", user.id },
		{ "email", user.email },
		{ "first_name", user.firstName },
		{ "last_name", user.lastName },
		{ "role", user.role }
	};

	return { CppHttp::Net::ResponseType::JSON, response.dump(4), {} };
}

returnType DeleteUser(CppHttp::Net::Request req) {
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
	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "SELECT * FROM users WHERE id = :id", soci::use(id), soci::into(user);
	}

	if (user.email.empty()) {
		return { CppHttp::Net::ResponseType::NOT_FOUND, "User not found", {} };
	}

	{
		std::lock_guard<std::mutex> lock(Database::dbMutex);
		*sql << "DELETE FROM users WHERE id = :id", soci::use(user.id);
	}

	json response = {
		{ "id", user.id },
		{ "email", user.email },
		{ "first_name", user.firstName },
		{ "last_name", user.lastName },
		{ "role", user.role }
	};

	return { CppHttp::Net::ResponseType::JSON, response.dump(4), {}};
}