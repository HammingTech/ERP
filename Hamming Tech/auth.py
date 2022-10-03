from urllib.parse import quote

import ham_t
import ham_t.database
import ham_t.utils
import ham_t.utils.user
from ham_t import _
from ham_t.core.doctype.activity_log.activity_log import add_authentication_log
from ham_t.sessions import Session, clear_sessions, delete_session
from ham_t.translate import get_language
from ham_t.twofactor import (
	authenticate_for_2factor,
	confirm_otp_token,
	get_cached_user_pass,
	should_run_2fa,
)
from ham_t.utils import cint, date_diff, datetime, get_datetime, today
from ham_t.utils.password import check_password
from ham_t.website.utils import get_home_page


class HTTPRequest:
	def __init__(self):
		# set ham_t.local.request_ip
		self.set_request_ip()

		# load cookies
		self.set_cookies()

		# login and start/resume user session
		self.set_session()

		# set request language
		self.set_lang()

		# match csrf token from current session
		self.validate_csrf_token()

		# write out latest cookies
		ham_t.local.cookie_manager.init_cookies()

	@property
	def domain(self):
		if not getattr(self, "_domain", None):
			self._domain = ham_t.request.host
			if self._domain and self._domain.startswith("www."):
				self._domain = self._domain[4:]

		return self._domain

	def set_request_ip(self):
		if ham_t.get_request_header("X-Forwarded-For"):
			ham_t.local.request_ip = (ham_t.get_request_header("X-Forwarded-For").split(",")[0]).strip()

		elif ham_t.get_request_header("REMOTE_ADDR"):
			ham_t.local.request_ip = ham_t.get_request_header("REMOTE_ADDR")

		else:
			ham_t.local.request_ip = "127.0.0.1"

	def set_cookies(self):
		ham_t.local.cookie_manager = CookieManager()

	def set_session(self):
		ham_t.local.login_manager = LoginManager()

	def validate_csrf_token(self):
		if ham_t.local.request and ham_t.local.request.method in ("POST", "PUT", "DELETE"):
			if not ham_t.local.session:
				return
			if (
				not ham_t.local.session.data.csrf_token
				or ham_t.local.session.data.device == "mobile"
				or ham_t.conf.get("ignore_csrf", None)
			):
				# not via boot
				return

			csrf_token = ham_t.get_request_header("X-ham_t-CSRF-Token")
			if not csrf_token and "csrf_token" in ham_t.local.form_dict:
				csrf_token = ham_t.local.form_dict.csrf_token
				del ham_t.local.form_dict["csrf_token"]

			if ham_t.local.session.data.csrf_token != csrf_token:
				ham_t.local.flags.disable_traceback = True
				ham_t.throw(_("Invalid Request"), ham_t.CSRFTokenError)

	def set_lang(self):
		ham_t.local.lang = get_language()


class LoginManager:

	__slots__ = ("user", "info", "full_name", "user_type", "resume")

	def __init__(self):
		self.user = None
		self.info = None
		self.full_name = None
		self.user_type = None

		if (
			ham_t.local.form_dict.get("cmd") == "login" or ham_t.local.request.path == "/api/method/login"
		):
			if self.login() is False:
				return
			self.resume = False

			# run login triggers
			self.run_trigger("on_session_creation")
		else:
			try:
				self.resume = True
				self.make_session(resume=True)
				self.get_user_info()
				self.set_user_info(resume=True)
			except AttributeError:
				self.user = "Guest"
				self.get_user_info()
				self.make_session()
				self.set_user_info()

	def login(self):
		if ham_t.get_system_settings("disable_user_pass_login"):
			ham_t.throw(_("Login with username and password is not allowed."), ham_t.AuthenticationError)

		# clear cache
		ham_t.clear_cache(user=ham_t.form_dict.get("usr"))
		user, pwd = get_cached_user_pass()
		self.authenticate(user=user, pwd=pwd)
		if self.force_user_to_reset_password():
			doc = ham_t.get_doc("User", self.user)
			ham_t.local.response["redirect_to"] = doc.reset_password(
				send_email=False, password_expired=True
			)
			ham_t.local.response["message"] = "Password Reset"
			return False

		if should_run_2fa(self.user):
			authenticate_for_2factor(self.user)
			if not confirm_otp_token(self):
				return False
		ham_t.form_dict.pop("pwd", None)
		self.post_login()

	def post_login(self):
		self.run_trigger("on_login")
		validate_ip_address(self.user)
		self.validate_hour()
		self.get_user_info()
		self.make_session()
		self.setup_boot_cache()
		self.set_user_info()

	def get_user_info(self):
		self.info = ham_t.get_cached_value(
			"User", self.user, ["user_type", "first_name", "last_name", "user_image"], as_dict=1
		)

		self.user_type = self.info.user_type

	def setup_boot_cache(self):
		ham_t.cache_manager.build_table_count_cache()
		ham_t.cache_manager.build_domain_restriced_doctype_cache()
		ham_t.cache_manager.build_domain_restriced_page_cache()

	def set_user_info(self, resume=False):
		# set sid again
		ham_t.local.cookie_manager.init_cookies()

		self.full_name = " ".join(filter(None, [self.info.first_name, self.info.last_name]))

		if self.info.user_type == "Website User":
			ham_t.local.cookie_manager.set_cookie("system_user", "no")
			if not resume:
				ham_t.local.response["message"] = "No App"
				ham_t.local.response["home_page"] = "/" + get_home_page()
		else:
			ham_t.local.cookie_manager.set_cookie("system_user", "yes")
			if not resume:
				ham_t.local.response["message"] = "Logged In"
				ham_t.local.response["home_page"] = "/app"

		if not resume:
			ham_t.response["full_name"] = self.full_name

		# redirect information
		redirect_to = ham_t.cache().hget("redirect_after_login", self.user)
		if redirect_to:
			ham_t.local.response["redirect_to"] = redirect_to
			ham_t.cache().hdel("redirect_after_login", self.user)

		ham_t.local.cookie_manager.set_cookie("full_name", self.full_name)
		ham_t.local.cookie_manager.set_cookie("user_id", self.user)
		ham_t.local.cookie_manager.set_cookie("user_image", self.info.user_image or "")

	def clear_preferred_language(self):
		ham_t.local.cookie_manager.delete_cookie("preferred_language")

	def make_session(self, resume=False):
		# start session
		ham_t.local.session_obj = Session(
			user=self.user, resume=resume, full_name=self.full_name, user_type=self.user_type
		)

		# reset user if changed to Guest
		self.user = ham_t.local.session_obj.user
		ham_t.local.session = ham_t.local.session_obj.data
		self.clear_active_sessions()

	def clear_active_sessions(self):
		"""Clear other sessions of the current user if `deny_multiple_sessions` is not set"""
		if ham_t.session.user == "Guest":
			return

		if not (
			cint(ham_t.conf.get("deny_multiple_sessions"))
			or cint(ham_t.db.get_system_setting("deny_multiple_sessions"))
		):
			return

		clear_sessions(ham_t.session.user, keep_current=True)

	def authenticate(self, user: str = None, pwd: str = None):
		from ham_t.core.doctype.user.user import User

		if not (user and pwd):
			user, pwd = ham_t.form_dict.get("usr"), ham_t.form_dict.get("pwd")
		if not (user and pwd):
			self.fail(_("Incomplete login details"), user=user)

		user = User.find_by_credentials(user, pwd)

		if not user:
			self.fail("Invalid login credentials")

		# Current login flow uses cached credentials for authentication while checking OTP.
		# Incase of OTP check, tracker for auth needs to be disabled(If not, it can remove tracker history as it is going to succeed anyway)
		# Tracker is activated for 2FA incase of OTP.
		ignore_tracker = should_run_2fa(user.name) and ("otp" in ham_t.form_dict)
		tracker = None if ignore_tracker else get_login_attempt_tracker(user.name)

		if not user.is_authenticated:
			tracker and tracker.add_failure_attempt()
			self.fail("Invalid login credentials", user=user.name)
		elif not (user.name == "Administrator" or user.enabled):
			tracker and tracker.add_failure_attempt()
			self.fail("User disabled or missing", user=user.name)
		else:
			tracker and tracker.add_success_attempt()
		self.user = user.name

	def force_user_to_reset_password(self):
		if not self.user:
			return

		if self.user in ham_t.STANDARD_USERS:
			return False

		reset_pwd_after_days = cint(
			ham_t.db.get_single_value("System Settings", "force_user_to_reset_password")
		)

		if reset_pwd_after_days:
			last_password_reset_date = (
				ham_t.db.get_value("User", self.user, "last_password_reset_date") or today()
			)

			last_pwd_reset_days = date_diff(today(), last_password_reset_date)

			if last_pwd_reset_days > reset_pwd_after_days:
				return True

	def check_password(self, user, pwd):
		"""check password"""
		try:
			# returns user in correct case
			return check_password(user, pwd)
		except ham_t.AuthenticationError:
			self.fail("Incorrect password", user=user)

	def fail(self, message, user=None):
		if not user:
			user = _("Unknown User")
		ham_t.local.response["message"] = message
		add_authentication_log(message, user, status="Failed")
		ham_t.db.commit()
		raise ham_t.AuthenticationError

	def run_trigger(self, event="on_login"):
		for method in ham_t.get_hooks().get(event, []):
			ham_t.call(ham_t.get_attr(method), login_manager=self)

	def validate_hour(self):
		"""check if user is logging in during restricted hours"""
		login_before = int(ham_t.db.get_value("User", self.user, "login_before", ignore=True) or 0)
		login_after = int(ham_t.db.get_value("User", self.user, "login_after", ignore=True) or 0)

		if not (login_before or login_after):
			return

		from ham_t.utils import now_datetime

		current_hour = int(now_datetime().strftime("%H"))

		if login_before and current_hour > login_before:
			ham_t.throw(_("Login not allowed at this time"), ham_t.AuthenticationError)

		if login_after and current_hour < login_after:
			ham_t.throw(_("Login not allowed at this time"), ham_t.AuthenticationError)

	def login_as_guest(self):
		"""login as guest"""
		self.login_as("Guest")

	def login_as(self, user):
		self.user = user
		self.post_login()

	def logout(self, arg="", user=None):
		if not user:
			user = ham_t.session.user
		self.run_trigger("on_logout")

		if user == ham_t.session.user:
			delete_session(ham_t.session.sid, user=user, reason="User Manually Logged Out")
			self.clear_cookies()
		else:
			clear_sessions(user)

	def clear_cookies(self):
		clear_cookies()


class CookieManager:
	def __init__(self):
		self.cookies = {}
		self.to_delete = []

	def init_cookies(self):
		if not ham_t.local.session.get("sid"):
			return

		# sid expires in 3 days
		expires = datetime.datetime.now() + datetime.timedelta(days=3)
		if ham_t.session.sid:
			self.set_cookie("sid", ham_t.session.sid, expires=expires, httponly=True)
		if ham_t.session.session_country:
			self.set_cookie("country", ham_t.session.session_country)

	def set_cookie(self, key, value, expires=None, secure=False, httponly=False, samesite="Lax"):
		if not secure and hasattr(ham_t.local, "request"):
			secure = ham_t.local.request.scheme == "https"

		# Cordova does not work with Lax
		if ham_t.local.session.data.device == "mobile":
			samesite = None

		self.cookies[key] = {
			"value": value,
			"expires": expires,
			"secure": secure,
			"httponly": httponly,
			"samesite": samesite,
		}

	def delete_cookie(self, to_delete):
		if not isinstance(to_delete, (list, tuple)):
			to_delete = [to_delete]

		self.to_delete.extend(to_delete)

	def flush_cookies(self, response):
		for key, opts in self.cookies.items():
			response.set_cookie(
				key,
				quote((opts.get("value") or "").encode("utf-8")),
				expires=opts.get("expires"),
				secure=opts.get("secure"),
				httponly=opts.get("httponly"),
				samesite=opts.get("samesite"),
			)

		# expires yesterday!
		expires = datetime.datetime.now() + datetime.timedelta(days=-1)
		for key in set(self.to_delete):
			response.set_cookie(key, "", expires=expires)


@ham_t.whitelist()
def get_logged_user():
	return ham_t.session.user


def clear_cookies():
	if hasattr(ham_t.local, "session"):
		ham_t.session.sid = ""
	ham_t.local.cookie_manager.delete_cookie(
		["full_name", "user_id", "sid", "user_image", "system_user"]
	)


def validate_ip_address(user):
	"""check if IP Address is valid"""
	from ham_t.core.doctype.user.user import get_restricted_ip_list

	# Only fetch required fields - for perf
	user_fields = ["restrict_ip", "bypass_restrict_ip_check_if_2fa_enabled"]
	user_info = (
		ham_t.get_cached_value("User", user, user_fields, as_dict=True)
		if not ham_t.flags.in_test
		else ham_t.db.get_value("User", user, user_fields, as_dict=True)
	)
	ip_list = get_restricted_ip_list(user_info)
	if not ip_list:
		return

	system_settings = (
		ham_t.get_cached_doc("System Settings")
		if not ham_t.flags.in_test
		else ham_t.get_single("System Settings")
	)
	# check if bypass restrict ip is enabled for all users
	bypass_restrict_ip_check = system_settings.bypass_restrict_ip_check_if_2fa_enabled

	# check if two factor auth is enabled
	if system_settings.enable_two_factor_auth and not bypass_restrict_ip_check:
		# check if bypass restrict ip is enabled for login user
		bypass_restrict_ip_check = user_info.bypass_restrict_ip_check_if_2fa_enabled

	for ip in ip_list:
		if ham_t.local.request_ip.startswith(ip) or bypass_restrict_ip_check:
			return

	ham_t.throw(_("Access not allowed from this IP Address"), ham_t.AuthenticationError)


def get_login_attempt_tracker(user_name: str, raise_locked_exception: bool = True):
	"""Get login attempt tracker instance.

	:param user_name: Name of the loggedin user
	:param raise_locked_exception: If set, raises an exception incase of user not allowed to login
	"""
	sys_settings = ham_t.get_doc("System Settings")
	track_login_attempts = sys_settings.allow_consecutive_login_attempts > 0
	tracker_kwargs = {}

	if track_login_attempts:
		tracker_kwargs["lock_interval"] = sys_settings.allow_login_after_fail
		tracker_kwargs["max_consecutive_login_attempts"] = sys_settings.allow_consecutive_login_attempts

	tracker = LoginAttemptTracker(user_name, **tracker_kwargs)

	if raise_locked_exception and track_login_attempts and not tracker.is_user_allowed():
		ham_t.throw(
			_("Your account has been locked and will resume after {0} seconds").format(
				sys_settings.allow_login_after_fail
			),
			ham_t.SecurityException,
		)
	return tracker


class LoginAttemptTracker:
	"""Track login attemts of a user.

	Lock the account for s number of seconds if there have been n consecutive unsuccessful attempts to log in.
	"""

	def __init__(
		self, user_name: str, max_consecutive_login_attempts: int = 3, lock_interval: int = 5 * 60
	):
		"""Initialize the tracker.

		:param user_name: Name of the loggedin user
		:param max_consecutive_login_attempts: Maximum allowed consecutive failed login attempts
		:param lock_interval: Locking interval incase of maximum failed attempts
		"""
		self.user_name = user_name
		self.lock_interval = datetime.timedelta(seconds=lock_interval)
		self.max_failed_logins = max_consecutive_login_attempts

	@property
	def login_failed_count(self):
		return ham_t.cache().hget("login_failed_count", self.user_name)

	@login_failed_count.setter
	def login_failed_count(self, count):
		ham_t.cache().hset("login_failed_count", self.user_name, count)

	@login_failed_count.deleter
	def login_failed_count(self):
		ham_t.cache().hdel("login_failed_count", self.user_name)

	@property
	def login_failed_time(self):
		"""First failed login attempt time within lock interval.

		For every user we track only First failed login attempt time within lock interval of time.
		"""
		return ham_t.cache().hget("login_failed_time", self.user_name)

	@login_failed_time.setter
	def login_failed_time(self, timestamp):
		ham_t.cache().hset("login_failed_time", self.user_name, timestamp)

	@login_failed_time.deleter
	def login_failed_time(self):
		ham_t.cache().hdel("login_failed_time", self.user_name)

	def add_failure_attempt(self):
		"""Log user failure attempts into the system.

		Increase the failure count if new failure is with in current lock interval time period, if not reset the login failure count.
		"""
		login_failed_time = self.login_failed_time
		login_failed_count = self.login_failed_count  # Consecutive login failure count
		current_time = get_datetime()

		if not (login_failed_time and login_failed_count):
			login_failed_time, login_failed_count = current_time, 0

		if login_failed_time + self.lock_interval > current_time:
			login_failed_count += 1
		else:
			login_failed_time, login_failed_count = current_time, 1

		self.login_failed_time = login_failed_time
		self.login_failed_count = login_failed_count

	def add_success_attempt(self):
		"""Reset login failures."""
		del self.login_failed_count
		del self.login_failed_time

	def is_user_allowed(self) -> bool:
		"""Is user allowed to login

		User is not allowed to login if login failures are greater than threshold within in lock interval from first login failure.
		"""
		login_failed_time = self.login_failed_time
		login_failed_count = self.login_failed_count or 0
		current_time = get_datetime()

		if (
			login_failed_time
			and login_failed_time + self.lock_interval > current_time
			and login_failed_count > self.max_failed_logins
		):
			return False
		return True
