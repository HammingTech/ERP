import json

import ham_t
from ham_t.desk.notifications import clear_notifications, delete_notification_count_for

common_default_keys = ["__default", "__global"]

doctype_map_keys = (
	"energy_point_rule_map",
	"assignment_rule_map",
	"milestone_tracker_map",
)

bench_cache_keys = ("assets_json",)

global_cache_keys = (
	"app_hooks",
	"installed_apps",
	"all_apps",
	"app_modules",
	"module_app",
	"system_settings",
	"scheduler_events",
	"time_zone",
	"webhooks",
	"active_domains",
	"active_modules",
	"assignment_rule",
	"server_script_map",
	"wkhtmltopdf_version",
	"domain_restricted_doctypes",
	"domain_restricted_pages",
	"information_schema:counts",
	"sitemap_routes",
	"db_tables",
	"server_script_autocompletion_items",
) + doctype_map_keys

user_cache_keys = (
	"bootinfo",
	"user_recent",
	"roles",
	"user_doc",
	"lang",
	"defaults",
	"user_permissions",
	"home_page",
	"linked_with",
	"desktop_icons",
	"portal_menu_items",
	"user_perm_can_read",
	"has_role:Page",
	"has_role:Report",
	"desk_sidebar_items",
)

doctype_cache_keys = (
	"doctype_meta",
	"doctype_form_meta",
	"table_columns",
	"last_modified",
	"linked_doctypes",
	"notifications",
	"workflow",
	"data_import_column_header_map",
) + doctype_map_keys


def clear_user_cache(user=None):
	cache = ham_t.cache()

	# this will automatically reload the global cache
	# so it is important to clear this first
	clear_notifications(user)

	if user:
		for name in user_cache_keys:
			cache.hdel(name, user)
		cache.delete_keys("user:" + user)
		clear_defaults_cache(user)
	else:
		for name in user_cache_keys:
			cache.delete_key(name)
		clear_defaults_cache()
		clear_global_cache()


def clear_domain_cache(user=None):
	cache = ham_t.cache()
	domain_cache_keys = ("domain_restricted_doctypes", "domain_restricted_pages")
	cache.delete_value(domain_cache_keys)


def clear_global_cache():
	from ham_t.website.utils import clear_website_cache

	clear_doctype_cache()
	clear_website_cache()
	ham_t.cache().delete_value(global_cache_keys)
	ham_t.cache().delete_value(bench_cache_keys)
	ham_t.setup_module_map()


def clear_defaults_cache(user=None):
	if user:
		for p in [user] + common_default_keys:
			ham_t.cache().hdel("defaults", p)
	elif ham_t.flags.in_install != "ham_t":
		ham_t.cache().delete_key("defaults")


def clear_doctype_cache(doctype=None):
	clear_controller_cache(doctype)
	cache = ham_t.cache()

	for key in ("is_table", "doctype_modules", "document_cache"):
		cache.delete_value(key)

	ham_t.local.document_cache = {}

	def clear_single(dt):
		for name in doctype_cache_keys:
			cache.hdel(name, dt)

	if doctype:
		clear_single(doctype)

		# clear all parent doctypes

		for dt in ham_t.get_all(
			"DocField", "parent", dict(fieldtype=["in", ham_t.model.table_fields], options=doctype)
		):
			clear_single(dt.parent)

		# clear all notifications
		delete_notification_count_for(doctype)

	else:
		# clear all
		for name in doctype_cache_keys:
			cache.delete_value(name)


def clear_controller_cache(doctype=None):
	if not doctype:
		del ham_t.controllers
		ham_t.controllers = {}
		return

	for site_controllers in ham_t.controllers.values():
		site_controllers.pop(doctype, None)


def get_doctype_map(doctype, name, filters=None, order_by=None):
	cache = ham_t.cache()
	cache_key = ham_t.scrub(doctype) + "_map"
	doctype_map = cache.hget(cache_key, name)

	if doctype_map is not None:
		# cached, return
		items = json.loads(doctype_map)
	else:
		# non cached, build cache
		try:
			items = ham_t.get_all(doctype, filters=filters, order_by=order_by)
			cache.hset(cache_key, name, json.dumps(items))
		except ham_t.db.TableMissingError:
			# executed from inside patch, ignore
			items = []

	return items


def clear_doctype_map(doctype, name):
	ham_t.cache().hdel(ham_t.scrub(doctype) + "_map", name)


def build_table_count_cache():
	if (
		ham_t.flags.in_patch
		or ham_t.flags.in_install
		or ham_t.flags.in_migrate
		or ham_t.flags.in_import
		or ham_t.flags.in_setup_wizard
	):
		return

	_cache = ham_t.cache()
	table_name = ham_t.qb.Field("table_name").as_("name")
	table_rows = ham_t.qb.Field("table_rows").as_("count")
	information_schema = ham_t.qb.Schema("information_schema")

	data = (ham_t.qb.from_(information_schema.tables).select(table_name, table_rows)).run(
		as_dict=True
	)
	counts = {d.get("name").replace("tab", "", 1): d.get("count", None) for d in data}
	_cache.set_value("information_schema:counts", counts)

	return counts


def build_domain_restriced_doctype_cache(*args, **kwargs):
	if (
		ham_t.flags.in_patch
		or ham_t.flags.in_install
		or ham_t.flags.in_migrate
		or ham_t.flags.in_import
		or ham_t.flags.in_setup_wizard
	):
		return
	_cache = ham_t.cache()
	active_domains = ham_t.get_active_domains()
	doctypes = ham_t.get_all("DocType", filters={"restrict_to_domain": ("IN", active_domains)})
	doctypes = [doc.name for doc in doctypes]
	_cache.set_value("domain_restricted_doctypes", doctypes)

	return doctypes


def build_domain_restriced_page_cache(*args, **kwargs):
	if (
		ham_t.flags.in_patch
		or ham_t.flags.in_install
		or ham_t.flags.in_migrate
		or ham_t.flags.in_import
		or ham_t.flags.in_setup_wizard
	):
		return
	_cache = ham_t.cache()
	active_domains = ham_t.get_active_domains()
	pages = ham_t.get_all("Page", filters={"restrict_to_domain": ("IN", active_domains)})
	pages = [page.name for page in pages]
	_cache.set_value("domain_restricted_pages", pages)

	return pages
