
import base64
import binascii
import json
from urllib.parse import urlencode, urlparse

import ham_t
import ham_t.client
import ham_t.handler
from ham_t import _
from ham_t.utils.data import sbool
from ham_t.utils.response import build_response


def handle():
	"""
	Handler for `/api` methods

	### Examples:

	`/api/method/{methodname}` will call a whitelisted method

	`/api/resource/{doctype}` will query a table
	        examples:
	        - `?fields=["name", "owner"]`
	        - `?filters=[["Task", "name", "like", "%005"]]`
	        - `?limit_start=0`
	        - `?limit_page_length=20`

	`/api/resource/{doctype}/{name}` will point to a resource
	        `GET` will return doclist
	        `POST` will insert
	        `PUT` will update
	        `DELETE` will delete

	`/api/resource/{doctype}/{name}?run_method={method}` will run a whitelisted controller method
	"""

	parts = ham_t.request.path[1:].split("/", 3)
	call = doctype = name = None

	if len(parts) > 1:
		call = parts[1]

	if len(parts) > 2:
		doctype = parts[2]

	if len(parts) > 3:
		name = parts[3]

	if call == "method":
		ham_t.local.form_dict.cmd = doctype
		return ham_t.handler.handle()

	elif call == "resource":
		if "run_method" in ham_t.local.form_dict:
			method = ham_t.local.form_dict.pop("run_method")
			doc = ham_t.get_doc(doctype, name)
			doc.is_whitelisted(method)

			if ham_t.local.request.method == "GET":
				if not doc.has_permission("read"):
					ham_t.throw(_("Not permitted"), ham_t.PermissionError)
				ham_t.local.response.update({"data": doc.run_method(method, **ham_t.local.form_dict)})

			if ham_t.local.request.method == "POST":
				if not doc.has_permission("write"):
					ham_t.throw(_("Not permitted"), ham_t.PermissionError)

				ham_t.local.response.update({"data": doc.run_method(method, **ham_t.local.form_dict)})
				ham_t.db.commit()

		else:
			if name:
				if ham_t.local.request.method == "GET":
					doc = ham_t.get_doc(doctype, name)
					if not doc.has_permission("read"):
						raise ham_t.PermissionError
					ham_t.local.response.update({"data": doc})

				if ham_t.local.request.method == "PUT":
					data = get_request_form_data()

					doc = ham_t.get_doc(doctype, name, for_update=True)

					if "flags" in data:
						del data["flags"]

					# Not checking permissions here because it's checked in doc.save
					doc.update(data)

					ham_t.local.response.update({"data": doc.save().as_dict()})

					# check for child table doctype
					if doc.get("parenttype"):
						ham_t.get_doc(doc.parenttype, doc.parent).save()

					ham_t.db.commit()

				if ham_t.local.request.method == "DELETE":
					# Not checking permissions here because it's checked in delete_doc
					ham_t.delete_doc(doctype, name, ignore_missing=False)
					ham_t.local.response.http_status_code = 202
					ham_t.local.response.message = "ok"
					ham_t.db.commit()

			elif doctype:
				if ham_t.local.request.method == "GET":
					# set fields for ham_t.get_list
					if ham_t.local.form_dict.get("fields"):
						ham_t.local.form_dict["fields"] = json.loads(ham_t.local.form_dict["fields"])

					# set limit of records for ham_t.get_list
					ham_t.local.form_dict.setdefault(
						"limit_page_length",
						ham_t.local.form_dict.limit or ham_t.local.form_dict.limit_page_length or 20,
					)

					# convert strings to native types - only as_dict and debug accept bool
					for param in ["as_dict", "debug"]:
						param_val = ham_t.local.form_dict.get(param)
						if param_val is not None:
							ham_t.local.form_dict[param] = sbool(param_val)

					# evaluate ham_t.get_list
					data = ham_t.call(ham_t.client.get_list, doctype, **ham_t.local.form_dict)

					# set ham_t.get_list result to response
					ham_t.local.response.update({"data": data})

				if ham_t.local.request.method == "POST":
					# fetch data from from dict
					data = get_request_form_data()
					data.update({"doctype": doctype})

					# insert document from request data
					doc = ham_t.get_doc(data).insert()

					# set response data
					ham_t.local.response.update({"data": doc.as_dict()})

					# commit for POST requests
					ham_t.db.commit()
			else:
				raise ham_t.DoesNotExistError

	else:
		raise ham_t.DoesNotExistError

	return build_response("json")


def get_request_form_data():
	if ham_t.local.form_dict.data is None:
		data = ham_t.safe_decode(ham_t.local.request.get_data())
	else:
		data = ham_t.local.form_dict.data

	try:
		return ham_t.parse_json(data)
	except ValueError:
		return ham_t.local.form_dict


def validate_auth():
	"""
	Authenticate and sets user for the request.
	"""
	authorization_header = ham_t.get_request_header("Authorization", "").split(" ")

	if len(authorization_header) == 2:
		validate_oauth(authorization_header)
		validate_auth_via_api_keys(authorization_header)

	validate_auth_via_hooks()


def validate_oauth(authorization_header):
	"""
	Authenticate request using OAuth and set session user

	Args:
	        authorization_header (list of str): The 'Authorization' header containing the prefix and token
	"""

	from ham_t.integrations.oauth2 import get_oauth_server
	from ham_t.oauth import get_url_delimiter

	form_dict = ham_t.local.form_dict
	token = authorization_header[1]
	req = ham_t.request
	parsed_url = urlparse(req.url)
	access_token = {"access_token": token}
	uri = (
		parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path + "?" + urlencode(access_token)
	)
	http_method = req.method
	headers = req.headers
	body = req.get_data()
	if req.content_type and "multipart/form-data" in req.content_type:
		body = None

	try:
		required_scopes = ham_t.db.get_value("OAuth Bearer Token", token, "scopes").split(
			get_url_delimiter()
		)
		valid, oauthlib_request = get_oauth_server().verify_request(
			uri, http_method, body, headers, required_scopes
		)
		if valid:
			ham_t.set_user(ham_t.db.get_value("OAuth Bearer Token", token, "user"))
			ham_t.local.form_dict = form_dict
	except AttributeError:
		pass


def validate_auth_via_api_keys(authorization_header):
	"""
	Authenticate request using API keys and set session user

	Args:
	        authorization_header (list of str): The 'Authorization' header containing the prefix and token
	"""

	try:
		auth_type, auth_token = authorization_header
		authorization_source = ham_t.get_request_header("ham_t-Authorization-Source")
		if auth_type.lower() == "basic":
			api_key, api_secret = ham_t.safe_decode(base64.b64decode(auth_token)).split(":")
			validate_api_key_secret(api_key, api_secret, authorization_source)
		elif auth_type.lower() == "token":
			api_key, api_secret = auth_token.split(":")
			validate_api_key_secret(api_key, api_secret, authorization_source)
	except binascii.Error:
		ham_t.throw(
			_("Failed to decode token, please provide a valid base64-encoded token."),
			ham_t.InvalidAuthorizationToken,
		)
	except (AttributeError, TypeError, ValueError):
		pass


def validate_api_key_secret(api_key, api_secret, ham_t_authorization_source=None):
	"""ham_t_authorization_source to provide api key and secret for a doctype apart from User"""
	doctype = ham_t_authorization_source or "User"
	doc = ham_t.db.get_value(doctype=doctype, filters={"api_key": api_key}, fieldname=["name"])
	form_dict = ham_t.local.form_dict
	doc_secret = ham_t.utils.password.get_decrypted_password(doctype, doc, fieldname="api_secret")
	if api_secret == doc_secret:
		if doctype == "User":
			user = ham_t.db.get_value(doctype="User", filters={"api_key": api_key}, fieldname=["name"])
		else:
			user = ham_t.db.get_value(doctype, doc, "user")
		if ham_t.local.login_manager.user in ("", "Guest"):
			ham_t.set_user(user)
		ham_t.local.form_dict = form_dict


def validate_auth_via_hooks():
	for auth_hook in ham_t.get_hooks("auth_hooks", []):
		ham_t.get_attr(auth_hook)()
