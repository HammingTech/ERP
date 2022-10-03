import logging
import os

from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.local import LocalManager
from werkzeug.middleware.profiler import ProfilerMiddleware
from werkzeug.middleware.shared_data import SharedDataMiddleware
from werkzeug.wrappers import Request, Response

import ham_t
import ham_t.api
import ham_t.auth
import ham_t.handler
import ham_t.monitor
import ham_t.rate_limiter
import ham_t.recorder
import ham_t.utils.response
from ham_t import _
from ham_t.core.doctype.comment.comment import update_comments_in_parent_after_request
from ham_t.middlewares import StaticDataMiddleware
from ham_t.utils import get_site_name, sanitize_html
from ham_t.utils.error import make_error_snapshot
from ham_t.website.serve import get_response

local_manager = LocalManager(ham_t.local)

_site = None
_sites_path = os.environ.get("SITES_PATH", ".")
SAFE_HTTP_METHODS = ("GET", "HEAD", "OPTIONS")
UNSAFE_HTTP_METHODS = ("POST", "PUT", "DELETE", "PATCH")


@local_manager.middleware
@Request.application
def application(request: Request):
	response = None

	try:
		rollback = True

		init_request(request)

		ham_t.recorder.record()
		ham_t.monitor.start()
		ham_t.rate_limiter.apply()
		ham_t.api.validate_auth()

		if request.method == "OPTIONS":
			response = Response()

		elif ham_t.form_dict.cmd:
			response = ham_t.handler.handle()

		elif request.path.startswith("/api/"):
			response = ham_t.api.handle()

		elif request.path.startswith("/backups"):
			response = ham_t.utils.response.download_backup(request.path)

		elif request.path.startswith("/private/files/"):
			response = ham_t.utils.response.download_private_file(request.path)

		elif request.method in ("GET", "HEAD", "POST"):
			response = get_response()

		else:
			raise NotFound

	except HTTPException as e:
		return e

	except Exception as e:
		response = handle_exception(e)

	else:
		rollback = after_request(rollback)

	finally:
		if request.method in ("POST", "PUT") and ham_t.db and rollback:
			ham_t.db.rollback()

		ham_t.rate_limiter.update()
		ham_t.monitor.stop(response)
		ham_t.recorder.dump()

		log_request(request, response)
		process_response(response)
		ham_t.destroy()

	return response


def init_request(request):
	ham_t.local.request = request
	ham_t.local.is_ajax = ham_t.get_request_header("X-Requested-With") == "XMLHttpRequest"

	site = _site or request.headers.get("X-ham_t-Site-Name") or get_site_name(request.host)
	ham_t.init(site=site, sites_path=_sites_path)

	if not (ham_t.local.conf and ham_t.local.conf.db_name):
		# site does not exist
		raise NotFound

	if ham_t.local.conf.maintenance_mode:
		ham_t.connect()
		if ham_t.local.conf.allow_reads_during_maintenance:
			setup_read_only_mode()
		else:
			raise ham_t.SessionStopped("Session Stopped")
	else:
		ham_t.connect(set_admin_as_user=False)

	request.max_content_length = ham_t.local.conf.get("max_file_size") or 10 * 1024 * 1024

	make_form_dict(request)

	if request.method != "OPTIONS":
		ham_t.local.http_request = ham_t.auth.HTTPRequest()


def setup_read_only_mode():
	"""During maintenance_mode reads to DB can still be performed to reduce downtime. This
	function sets up read only mode

	- Setting global flag so other pages, desk and database can know that we are in read only mode.
	- Setup read only database access either by:
	    - Connecting to read replica if one exists
	    - Or setting up read only SQL transactions.
	"""
	ham_t.flags.read_only = True

	# If replica is available then just connect replica, else setup read only transaction.
	if ham_t.conf.read_from_replica:
		ham_t.connect_replica()
	else:
		ham_t.db.begin(read_only=True)


def log_request(request, response):
	if hasattr(ham_t.local, "conf") and ham_t.local.conf.enable_ham_t_logger:
		ham_t.logger("ham_t.web", allow_site=ham_t.local.site).info(
			{
				"site": get_site_name(request.host),
				"remote_addr": getattr(request, "remote_addr", "NOTFOUND"),
				"base_url": getattr(request, "base_url", "NOTFOUND"),
				"full_path": getattr(request, "full_path", "NOTFOUND"),
				"method": getattr(request, "method", "NOTFOUND"),
				"scheme": getattr(request, "scheme", "NOTFOUND"),
				"http_status_code": getattr(response, "status_code", "NOTFOUND"),
			}
		)


def process_response(response):
	if not response:
		return

	# set cookies
	if hasattr(ham_t.local, "cookie_manager"):
		ham_t.local.cookie_manager.flush_cookies(response=response)

	# rate limiter headers
	if hasattr(ham_t.local, "rate_limiter"):
		response.headers.extend(ham_t.local.rate_limiter.headers())

	# CORS headers
	if hasattr(ham_t.local, "conf"):
		set_cors_headers(response)


def set_cors_headers(response):
	if not (
		(allowed_origins := ham_t.conf.allow_cors)
		and (request := ham_t.local.request)
		and (origin := request.headers.get("Origin"))
	):
		return

	if allowed_origins != "*":
		if not isinstance(allowed_origins, list):
			allowed_origins = [allowed_origins]

		if origin not in allowed_origins:
			return

	cors_headers = {
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Origin": origin,
		"Vary": "Origin",
	}

	# only required for preflight requests
	if request.method == "OPTIONS":
		cors_headers["Access-Control-Allow-Methods"] = request.headers.get(
			"Access-Control-Request-Method"
		)

		if allowed_headers := request.headers.get("Access-Control-Request-Headers"):
			cors_headers["Access-Control-Allow-Headers"] = allowed_headers

		# allow browsers to cache preflight requests for upto a day
		if not ham_t.conf.developer_mode:
			cors_headers["Access-Control-Max-Age"] = "86400"

	response.headers.extend(cors_headers)


def make_form_dict(request):
	import json

	request_data = request.get_data(as_text=True)
	if "application/json" in (request.content_type or "") and request_data:
		args = json.loads(request_data)
	else:
		args = {}
		args.update(request.args or {})
		args.update(request.form or {})

	if not isinstance(args, dict):
		ham_t.throw(_("Invalid request arguments"))

	ham_t.local.form_dict = ham_t._dict(args)

	if "_" in ham_t.local.form_dict:
		# _ is passed by $.ajax so that the request is not cached by the browser. So, remove _ from form_dict
		ham_t.local.form_dict.pop("_")


def handle_exception(e):
	response = None
	http_status_code = getattr(e, "http_status_code", 500)
	return_as_message = False
	accept_header = ham_t.get_request_header("Accept") or ""
	respond_as_json = (
		ham_t.get_request_header("Accept")
		and (ham_t.local.is_ajax or "application/json" in accept_header)
		or (ham_t.local.request.path.startswith("/api/") and not accept_header.startswith("text"))
	)

	if not ham_t.session.user:
		# If session creation fails then user won't be unset. This causes a lot of code that
		# assumes presence of this to fail. Session creation fails => guest or expired login
		# usually.
		ham_t.session.user = "Guest"

	if respond_as_json:
		# handle ajax responses first
		# if the request is ajax, send back the trace or error message
		response = ham_t.utils.response.report_error(http_status_code)

	elif isinstance(e, ham_t.SessionStopped):
		response = ham_t.utils.response.handle_session_stopped()

	elif (
		http_status_code == 500
		and (ham_t.db and isinstance(e, ham_t.db.InternalError))
		and (ham_t.db and (ham_t.db.is_deadlocked(e) or ham_t.db.is_timedout(e)))
	):
		http_status_code = 508

	elif http_status_code == 401:
		ham_t.respond_as_web_page(
			_("Session Expired"),
			_("Your session has expired, please login again to continue."),
			http_status_code=http_status_code,
			indicator_color="red",
		)
		return_as_message = True

	elif http_status_code == 403:
		ham_t.respond_as_web_page(
			_("Not Permitted"),
			_("You do not have enough permissions to complete the action"),
			http_status_code=http_status_code,
			indicator_color="red",
		)
		return_as_message = True

	elif http_status_code == 404:
		ham_t.respond_as_web_page(
			_("Not Found"),
			_("The resource you are looking for is not available"),
			http_status_code=http_status_code,
			indicator_color="red",
		)
		return_as_message = True

	elif http_status_code == 429:
		response = ham_t.rate_limiter.respond()

	else:
		traceback = "<pre>" + sanitize_html(ham_t.get_traceback()) + "</pre>"
		# disable traceback in production if flag is set
		if ham_t.local.flags.disable_traceback and not ham_t.local.dev_server:
			traceback = ""

		ham_t.respond_as_web_page(
			"Server Error", traceback, http_status_code=http_status_code, indicator_color="red", width=640
		)
		return_as_message = True

	if e.__class__ == ham_t.AuthenticationError:
		if hasattr(ham_t.local, "login_manager"):
			ham_t.local.login_manager.clear_cookies()

	if http_status_code >= 500:
		make_error_snapshot(e)

	if return_as_message:
		response = get_response("message", http_status_code=http_status_code)

	if ham_t.conf.get("developer_mode") and not respond_as_json:
		# don't fail silently for non-json response errors
		print(ham_t.get_traceback())

	return response


def after_request(rollback):
	# if HTTP method would change server state, commit if necessary
	if ham_t.db and (
		ham_t.local.flags.commit or ham_t.local.request.method in UNSAFE_HTTP_METHODS
	):
		if ham_t.db.transaction_writes:
			ham_t.db.commit()
			rollback = False

	# update session
	if getattr(ham_t.local, "session_obj", None):
		updated_in_db = ham_t.local.session_obj.update()
		if updated_in_db:
			ham_t.db.commit()
			rollback = False

	update_comments_in_parent_after_request()

	return rollback


def serve(
	port=8000, profile=False, no_reload=False, no_threading=False, site=None, sites_path="."
):
	global application, _site, _sites_path
	_site = site
	_sites_path = sites_path

	from werkzeug.serving import run_simple

	if profile or os.environ.get("USE_PROFILER"):
		application = ProfilerMiddleware(application, sort_by=("cumtime", "calls"))

	if not os.environ.get("NO_STATICS"):
		application = SharedDataMiddleware(
			application, {"/assets": str(os.path.join(sites_path, "assets"))}
		)

		application = StaticDataMiddleware(application, {"/files": str(os.path.abspath(sites_path))})

	application.debug = True
	application.config = {"SERVER_NAME": "localhost:8000"}

	log = logging.getLogger("werkzeug")
	log.propagate = False

	in_test_env = os.environ.get("CI")
	if in_test_env:
		log.setLevel(logging.ERROR)

	run_simple(
		"0.0.0.0",
		int(port),
		application,
		use_reloader=False if in_test_env else not no_reload,
		use_debugger=not in_test_env,
		use_evalex=not in_test_env,
		threaded=not no_threading,
	)
