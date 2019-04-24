/* Icinga 2 | (c) 2012 Icinga GmbH | GPLv2+ */

#include "icinga-version.h" /* include VERSION */

#include "base/application.hpp"
#include "base/json.hpp"
#include "base/string.hpp"
#include "base/logger.hpp"
#include "base/exception.hpp"
#include "base/utility.hpp"
#include "base/convert.hpp"
#include "base/networkstream.hpp"
#include "base/defer.hpp"
#include "base/io-engine.hpp"
#include "base/stream.hpp"
#include "base/tcpsocket.hpp" /* include global icinga::Connect */
#include "base/tlsstream.hpp"
#include "base/base64.hpp"
#include "remote/url.hpp"
#include <remote/url-characters.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/http/write.hpp>
#include <iostream>

using namespace icinga;
namespace po = boost::program_options;

static bool l_Debug;

/*
 * Takes a Dictionary 'result' and constructs an icinga compliant output string.
 * If 'result' is not in the expected format it returns 3 ("UNKNOWN") and prints an informative, icinga compliant,
 * output string.
 */
static int FormatOutput(const Dictionary::Ptr& result)
{
	if (!result) {
		std::cerr << "UNKNOWN: No data received.\n";
		return 3;
	}

	if (l_Debug)
		std::cout << "\tJSON Body:\n" << result->ToString() << '\n';

	Array::Ptr payloads = result->Get("payload");
	if (!payloads) {
		std::cerr << "UNKNOWN: Answer format error: Answer is missing 'payload'.\n";
		return 3;
	}

	if (payloads->GetLength() == 0) {
		std::cerr << "UNKNOWN: Answer format error: 'payload' was empty.\n";
		return 3;
	}

	if (payloads->GetLength() > 1) {
		std::cerr << "UNKNOWN: Answer format error: Multiple payloads are not supported.";
		return 3;
	}

	Dictionary::Ptr payload;
	try {
		payload = payloads->Get(0);
	} catch (const std::exception&) {
		std::cerr << "UNKNOWN: Answer format error: 'payload' was not a Dictionary.\n";
		return 3;
	}

	Array::Ptr lines;
	try {
		lines = payload->Get("lines");
	} catch (const std::exception&) {
		std::cerr << "UNKNOWN: Answer format error: 'payload' is missing 'lines'.\n";
		return 3;
	}

	if (!lines) {
		std::cerr << "UNKNOWN: Answer format error: 'lines' is Null.\n";
		return 3;
	}

	std::stringstream ssout;
	ObjectLock olock(lines);

	for (const Value& vline : lines) {
		Dictionary::Ptr line;
		try {
			line = vline;
		} catch (const std::exception&) {
			std::cerr << "UNKNOWN: Answer format error: 'lines' entry was not a Dictionary.\n";
			return 3;
		}
		if (!line) {
			std::cerr << "UNKNOWN: Answer format error: 'lines' entry was Null.\n";
			return 3;
		}

		ssout << payload->Get("command") << ' ' << line->Get("message") << " | ";

		if (!line->Contains("perf")) {
			ssout << '\n';
			break;
		}

		Array::Ptr perfs = line->Get("perf");
		ObjectLock olock(perfs);

		for (const Dictionary::Ptr& perf : perfs) {
			ssout << "'" << perf->Get("alias") << "'=";
			Dictionary::Ptr values = perf->Contains("int_value") ? perf->Get("int_value") : perf->Get("float_value");
			ssout << values->Get("value") << values->Get("unit") << ';' << values->Get("warning") << ';' << values->Get("critical");

			if (values->Contains("minimum") || values->Contains("maximum")) {
				ssout << ';';

				if (values->Contains("minimum"))
					ssout << values->Get("minimum");

				if (values->Contains("maximum"))
					ssout << ';' << values->Get("maximum");
			}

			ssout << ' ';
		}

		ssout << '\n';
	}

	//TODO: Fix
	String state = static_cast<String>(payload->Get("result")).ToUpper();
	int creturn = state == "OK" ? 0 :
		state == "WARNING" ? 1 :
		state == "CRITICAL" ? 2 :
		state == "UNKNOWN" ? 3 : 4;

	if (creturn == 4) {
		std::cerr << "UNKNOWN Answer format error: 'result' was not a known state.\n";
		return 3;
	}

	std::cout << ssout.rdbuf();
	return creturn;
}

/**
 * Connects to host:port and performs a TLS shandshake
 *
 * @param host To connect to.
 * @param port To connect to.
 *
 * @returns AsioTlsStream pointer for future HTTP connections.
 */
static std::shared_ptr<AsioTlsStream> Connect(const String& host, const String& port)
{
	std::shared_ptr<boost::asio::ssl::context> sslContext;

	try {
		sslContext = MakeAsioSslContext(Empty, Empty, Empty); //TODO: Add support for cert, key, ca parameters
	} catch(const std::exception& ex) {
		Log(LogCritical, "DebugConsole")
			<< "Cannot make SSL context: " << ex.what();
		throw;
	}

	std::shared_ptr<AsioTlsStream> stream = std::make_shared<AsioTlsStream>(IoEngine::Get().GetIoService(), *sslContext, host);

	try {
		icinga::Connect(stream->lowest_layer(), host, port);
	} catch (const std::exception& ex) {
		Log(LogWarning, "DebugConsole")
			<< "Cannot connect to REST API on host '" << host << "' port '" << port << "': " << ex.what();
		throw;
	}

	auto& tlsStream (stream->next_layer());

	try {
		tlsStream.handshake(tlsStream.client);
	} catch (const std::exception& ex) {
		Log(LogWarning, "DebugConsole")
			<< "TLS handshake with host '" << host << "' failed: " << ex.what();
		throw;
	}

	return std::move(stream);
}

static Dictionary::Ptr FetchData(const String& host, const String& port, const String& password,
	const String& endpoint)
{
	namespace beast = boost::beast;
	namespace http = beast::http;


	std::shared_ptr<AsioTlsStream> tlsStream;

	try {
		tlsStream = Connect(host, port);
	} catch (const std::exception& ex) {
		std::cerr << "Connection error: " << ex.what();
		throw ex;
	}

	Url::Ptr url;

	try {
		url = new Url(endpoint);
	} catch (const std::exception& ex) {
		std::cerr << "URL error: " << ex.what();
		throw ex;
	}

	url->SetScheme("https");
	url->SetHost(host);
	url->SetPort(port);

	// NSClient++ uses `time=1m&time=5m` instead of `time[]=1m&time[]=5m`
	url->SetArrayFormatUseBrackets(false);

	http::request<http::string_body> request (http::verb::get, std::string(url->Format(true)), 10);

	request.set(http::field::user_agent, "Icinga/check_nscp_api/" + Convert::ToString(VERSION));
	request.set(http::field::host, host + ":" + port);

	request.set(http::field::accept, "application/json");
	request.set("password", password);

	if (l_Debug) {
		std::cout << "Sending request to " << url->Format(false, false) << "'.\n";
	}

	try {
		http::write(*tlsStream, request);
		tlsStream->flush();
	} catch (const std::exception& ex) {
		std::cerr << "Cannot write HTTP request to REST API at URL '" << url->Format(false, false) << "': " << ex.what();
		throw ex;
	}


	http::parser<false, http::string_body> parser;
	//http::response<http::string_body> response;
	beast::flat_buffer buf;
	boost::system::error_code ec;

	/*
	try {
		http::read(*tlsStream, buf, parser);
	} catch (const boost::system::system_error& ex) {
		// Workaround for missing status/reason phrase in NSCP, https://github.com/mickem/nscp/issues/610
		if (ex.code() != http::error::bad_reason && ex.code() != http::error::bad_status) {
			std::cerr << "Failed to parse HTTP response from REST API at URL '" << url->Format(false, false) << "': "
					  << ex.what();
			throw ex;
		} else {

		}
	}
	 */

	/*
	http::read_header(*tlsStream, buf, parser, ec);

	//This will always fail since NSClient's header is not RFC conform. https://github.com/mickem/nscp/issues/610
	if (ec)
		std::cerr << "Error reading header: " << ec.message();
*/
	/* https://www.boost.org/doc/libs/1_68_0/libs/beast/doc/html/beast/using_http/buffer_oriented_parsing.html
	 *
	 * Normally the parser returns after successfully parsing a structured element (header, chunk header, or chunk body)
	 * even if there are octets remaining in the input. This is necessary when attempting to parse the header first, or
	 * when the caller wants to inspect information which may be invalidated by subsequent parsing, such as a chunk extension.
	 * The eager option controls whether the parser keeps going after parsing structured element if there are octets remaining
	 * in the buffer and no error occurs. This option is automatically set or cleared during certain stream operations to improve
	 * performance with no change in functionality.
	 */
	parser.eager(true);

	http::read(*tlsStream, buf, parser, ec);

	if (ec)
		std::cerr << "Error reading body: " << ec.message();

	auto& response (parser.get());

	// Handle HTTP errors first. Unfortunately NSClient treats every request as OK. */
	if (response.result() != http::status::ok) {
		std::string message = "HTTP request failed; Code: " + Convert::ToString(response.result()) + "; Body: " + response.body();
		BOOST_THROW_EXCEPTION(ScriptError(message));
	}

	auto& body (response.body());

	if (l_Debug) {
		std::cout << "Received answer\n"
				  << "\tHTTP code: " << response.result() << "\n"
				  << "\tHTTP body: '" << response.body() << "'.\n";
	}

	Dictionary::Ptr jsonResponse;

	try {
		jsonResponse = JsonDecode(body);
	} catch (...) {
		std::string message = "Cannot parse JSON response body: " + body;
		BOOST_THROW_EXCEPTION(ScriptError(message));
	}


	return jsonResponse;
}

/*
 *  Process arguments, initialize environment and shut down gracefully.
 */
int main(int argc, char **argv)
{
	po::variables_map vm;
	po::options_description desc("Options");

	desc.add_options()
		("help,h", "Print usage message and exit")
		("version,V", "Print version and exit")
		("debug,d", "Verbose/Debug output")
		("host,H", po::value<std::string>()->required(), "REQUIRED: NSCP API Host")
		("port,P", po::value<std::string>()->default_value("8443"), "NSCP API Port (Default: 8443)")
		("password", po::value<std::string>()->required(), "REQUIRED: NSCP API Password")
		("query,q", po::value<std::string>()->required(), "REQUIRED: NSCP API Query endpoint")
		("arguments,a", po::value<std::vector<std::string>>()->multitoken(), "NSCP API Query arguments for the endpoint");

	po::command_line_parser parser(argc, argv);

	try {
		po::store(
			parser
			.options(desc)
			.style(
				po::command_line_style::unix_style |
				po::command_line_style::allow_long_disguise)
			.run(),
			vm);

		if (vm.count("version")) {
			std::cout << "Version: " << VERSION << '\n';
			Application::Exit(0);
		}

		if (vm.count("help")) {
			std::cout << argv[0] << " Help\n\tVersion: " << VERSION << '\n';
			std::cout << "check_nscp_api is a program used to query the NSClient++ API.\n";
			std::cout << desc;
			std::cout << "For detailed information on possible queries and their arguments refer to the NSClient++ documentation.\n";
			Application::Exit(0);
		}

		vm.notify();
	} catch (const std::exception& e) {
		std::cout << e.what() << '\n' << desc << '\n';
		Application::Exit(3);
	}

	l_Debug = vm.count("debug") > 0;

	// Initialize logger
	if (l_Debug)
		Logger::SetConsoleLogSeverity(LogDebug);
	else
		Logger::SetConsoleLogSeverity(LogWarning);

	// Create the URL string and escape certain characters since Url() follows RFC 3986
	String endpoint = "/query/" + vm["query"].as<std::string>();
	if (!vm.count("arguments"))
		endpoint += '/';
	else {
		endpoint += '?';
		for (const String& argument : vm["arguments"].as<std::vector<std::string>>()) {
			String::SizeType pos = argument.FindFirstOf("=");
			if (pos == String::NPos)
				endpoint += Utility::EscapeString(argument, ACQUERY_ENCODE, false);
			else {
				String key = argument.SubStr(0, pos);
				String val = argument.SubStr(pos + 1);
				endpoint += Utility::EscapeString(key, ACQUERY_ENCODE, false) + "=" + Utility::EscapeString(val, ACQUERY_ENCODE, false);
			}
			endpoint += '&';
		}
	}

	Dictionary::Ptr result;

	try {
		result = FetchData(vm["host"].as<std::string>(), vm["port"].as<std::string>(),
		   vm["password"].as<std::string>(), endpoint);
	} catch (const std::exception& ex) {
		std::cerr << "UNKNOWN - " << ex.what();
		exit(3);
	}

	// Application::Exit() is the clean way to exit after calling InitializeBase()
	Application::Exit(FormatOutput(result));
	return 255;
}
