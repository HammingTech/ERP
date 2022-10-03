# Copyright (c) 2022, ham_t Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE

import os
from mimetypes import guess_type
from typing import TYPE_CHECKING

from werkzeug.wrappers import Response

import ham_t
import ham_t.sessions
import ham_t.utils
from ham_t import _, is_whitelisted
from ham_t.core.doctype.server_script.server_script_utils import get_server_script_map
from ham_t.utils import cint
from ham_t.utils.csvutils import build_csv_response
from ham_t.utils.image import optimize_image
from ham_t.utils.response import build_response

if TYPE_CHECKING:
	from ham_t.core.doctype.file.file import File
	from ham_t.core.doctype.user.user import User

ALLOWED_MIMETYPES = (
	"image/png",
	"image/jpeg",
	"application/pdf",
	"application/msword",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.ms-excel",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.oasis.opendocument.text",
	"application/vnd.oasis.opendocument.spreadsheet",
	"text/plain",
)


def handle():
	"""handle request"""

	cmd = ham_t.local.form_dict.cmd
	data = None

	if cmd != "login":
		data = execute_cmd(cmd)

	# data can be an empty string or list which are valid responses
	if data is not None:
		if isinstance(data, Response):
			# method returns a response object, pass it on
			return data

		# add the response to `message` label
		ham_t.response["message"] = data

	return build_response("json")


def execute_cmd(cmd, from_async=False):
	"""execute a request as python module"""
	for hook in ham_t.get_hooks("override_whitelisted_methods", {}).get(cmd, []):
		# override using the first hook
		cmd = hook
		break

	# via server script
	server_script = get_server_script_map().get("_api", {}).get(cmd)
	if server_script:
		return run_server_script(server_script)

	try:
		method = get_attr(cmd)
	except Exception as e:
		ham_t.throw(_("Failed to get method for command {0} with {1}").format(cmd, e))

	if from_async:
		method = method.queue

	if method != run_doc_method:
		is_whitelisted(method)
		is_valid_http_method(method)

	return ham_t.call(method, **ham_t.form_dict)


def run_server_script(server_script):
	response = ham_t.get_doc("Server Script", server_script).execute_method()

	# some server scripts return output using flags (empty dict by default),
	# while others directly modify ham_t.response
	# return flags if not empty dict (this overwrites ham_t.response.message)
	if response != {}:
		return response


def is_valid_http_method(method):
	if ham_t.flags.in_safe_exec:
		return

	http_method = ham_t.local.request.method

	if http_method not in ham_t.allowed_http_methods_for_whitelisted_func[method]:
		throw_permission_error()


def throw_permission_error():
	ham_t.throw(_("Not permitted"), ham_t.PermissionError)


@ham_t.whitelist(allow_guest=True)
def version():
	return ham_t.__version__


@ham_t.whitelist(allow_guest=True)
def logout():
	ham_t.local.login_manager.logout()
	ham_t.db.commit()


@ham_t.whitelist(allow_guest=True)
def web_logout():
	ham_t.local.login_manager.logout()
	ham_t.db.commit()
	ham_t.respond_as_web_page(
		_("Logged Out"), _("You have been successfully logged out"), indicator_color="green"
	)


@ham_t.whitelist()
def uploadfile():
	ret = None

	try:
		if ham_t.form_dict.get("from_form"):
			try:
				ret = ham_t.get_doc(
					{
						"doctype": "File",
						"attached_to_name": ham_t.form_dict.docname,
						"attached_to_doctype": ham_t.form_dict.doctype,
						"attached_to_field": ham_t.form_dict.docfield,
						"file_url": ham_t.form_dict.file_url,
						"file_name": ham_t.form_dict.filename,
						"is_private": ham_t.utils.cint(ham_t.form_dict.is_private),
						"content": ham_t.form_dict.filedata,
						"decode": True,
					}
				)
				ret.save()
			except ham_t.DuplicateEntryError:
				# ignore pass
				ret = None
				ham_t.db.rollback()
		else:
			if ham_t.form_dict.get("method"):
				method = ham_t.get_attr(ham_t.form_dict.method)
				is_whitelisted(method)
				ret = method()
	except Exception:
		ham_t.errprint(ham_t.utils.get_traceback())
		ham_t.response["http_status_code"] = 500
		ret = None

	return ret


@ham_t.whitelist(allow_guest=True)
def upload_file():
	user = None
	if ham_t.session.user == "Guest":
		if ham_t.get_system_settings("allow_guests_to_upload_files"):
			ignore_permissions = True
		else:
			raise ham_t.PermissionError
	else:
		user: "User" = ham_t.get_doc("User", ham_t.session.user)
		ignore_permissions = False

	files = ham_t.request.files
	is_private = ham_t.form_dict.is_private
	doctype = ham_t.form_dict.doctype
	docname = ham_t.form_dict.docname
	fieldname = ham_t.form_dict.fieldname
	file_url = ham_t.form_dict.file_url
	folder = ham_t.form_dict.folder or "Home"
	method = ham_t.form_dict.method
	filename = ham_t.form_dict.file_name
	optimize = ham_t.form_dict.optimize
	content = None

	if "file" in files:
		file = files["file"]
		content = file.stream.read()
		filename = file.filename

		content_type = guess_type(filename)[0]
		if optimize and content_type.startswith("image/"):
			args = {"content": content, "content_type": content_type}
			if ham_t.form_dict.max_width:
				args["max_width"] = int(ham_t.form_dict.max_width)
			if ham_t.form_dict.max_height:
				args["max_height"] = int(ham_t.form_dict.max_height)
			content = optimize_image(**args)

	ham_t.local.uploaded_file = content
	ham_t.local.uploaded_filename = filename

	if content is not None and (
		ham_t.session.user == "Guest" or (user and not user.has_desk_access())
	):
		filetype = guess_type(filename)[0]
		if filetype not in ALLOWED_MIMETYPES:
			ham_t.throw(_("You can only upload JPG, PNG, PDF, TXT or Microsoft documents."))

	if method:
		method = ham_t.get_attr(method)
		is_whitelisted(method)
		return method()
	else:
		return ham_t.get_doc(
			{
				"doctype": "File",
				"attached_to_doctype": doctype,
				"attached_to_name": docname,
				"attached_to_field": fieldname,
				"folder": folder,
				"file_name": filename,
				"file_url": file_url,
				"is_private": cint(is_private),
				"content": content,
			}
		).save(ignore_permissions=ignore_permissions)


@ham_t.whitelist(allow_guest=True)
def download_file(file_url: str):
	"""
	Download file using token and REST API. Valid session or
	token is required to download private files.

	Method : GET
	Endpoints : download_file, ham_t.core.doctype.file.file.download_file
	URL Params : file_name = /path/to/file relative to site path
	"""
	file: "File" = ham_t.get_doc("File", {"file_url": file_url})
	if not file.is_downloadable():
		raise ham_t.PermissionError

	ham_t.local.response.filename = os.path.basename(file_url)
	ham_t.local.response.filecontent = file.get_content()
	ham_t.local.response.type = "download"


def get_attr(cmd):
	"""get method object from cmd"""
	if "." in cmd:
		method = ham_t.get_attr(cmd)
	else:
		method = globals()[cmd]
	ham_t.log("method:" + cmd)
	return method


@ham_t.whitelist(allow_guest=True)
def ping():
	return "pong"


def run_doc_method(method, docs=None, dt=None, dn=None, arg=None, args=None):
	"""run a whitelisted controller method"""
	from inspect import getfullargspec

	if not args and arg:
		args = arg

	if dt:  # not called from a doctype (from a page)
		if not dn:
			dn = dt  # single
		doc = ham_t.get_doc(dt, dn)

	else:
		docs = ham_t.parse_json(docs)
		doc = ham_t.get_doc(docs)
		doc._original_modified = doc.modified
		doc.check_if_latest()

	if not doc or not doc.has_permission("read"):
		throw_permission_error()

	try:
		args = ham_t.parse_json(args)
	except ValueError:
		pass

	method_obj = getattr(doc, method)
	fn = getattr(method_obj, "__func__", method_obj)
	is_whitelisted(fn)
	is_valid_http_method(fn)

	fnargs = getfullargspec(method_obj).args

	if not fnargs or (len(fnargs) == 1 and fnargs[0] == "self"):
		response = doc.run_method(method)

	elif "args" in fnargs or not isinstance(args, dict):
		response = doc.run_method(method, args)

	else:
		response = doc.run_method(method, **args)

	ham_t.response.docs.append(doc)
	if response is None:
		return

	# build output as csv
	if cint(ham_t.form_dict.get("as_csv")):
		build_csv_response(response, _(doc.doctype).replace(" ", ""))
		return

	ham_t.response["message"] = response


# for backwards compatibility
runserverobj = run_doc_method
