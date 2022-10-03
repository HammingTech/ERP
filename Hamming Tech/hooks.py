from . import __version__ as app_version

app_name = "ham_t"
app_title = "ham_t Framework"
app_publisher = "ham_t Technologies"
app_description = "Full stack web framework with Python, Javascript, MariaDB, Redis, Node"
source_link = "https://github.com/ham_t/ham_t"
app_license = "MIT"
app_logo_url = "/assets/ham_t/images/ham_t-framework-logo.svg"

develop_version = "14.x.x-develop"

app_email = "developers@ham_t.io"

docs_app = "ham_t_docs"

translator_url = "https://translate.erpnext.com"

before_install = "ham_t.utils.install.before_install"
after_install = "ham_t.utils.install.after_install"

page_js = {"setup-wizard": "public/js/ham_t/setup_wizard.js"}

# website
app_include_js = [
	"libs.bundle.js",
	"desk.bundle.js",
	"list.bundle.js",
	"form.bundle.js",
	"controls.bundle.js",
	"report.bundle.js",
]
app_include_css = [
	"desk.bundle.css",
	"report.bundle.css",
]

doctype_js = {
	"Web Page": "public/js/ham_t/utils/web_template.js",
	"Website Settings": "public/js/ham_t/utils/web_template.js",
}

web_include_js = ["website_script.js"]

web_include_css = []

email_css = ["email.bundle.css"]

website_route_rules = [
	{"from_route": "/blog/<category>", "to_route": "Blog Post"},
	{"from_route": "/kb/<category>", "to_route": "Help Article"},
	{"from_route": "/newsletters", "to_route": "Newsletter"},
	{"from_route": "/profile", "to_route": "me"},
	{"from_route": "/app/<path:app_path>", "to_route": "app"},
]

website_redirects = [
	{"source": r"/desk(.*)", "target": r"/app\1"},
]

base_template = "templates/base.html"

write_file_keys = ["file_url", "file_name"]

notification_config = "ham_t.core.notifications.get_notification_config"

before_tests = "ham_t.utils.install.before_tests"

email_append_to = ["Event", "ToDo", "Communication"]

calendars = ["Event"]

leaderboards = "ham_t.desk.leaderboard.get_leaderboards"

# login

on_session_creation = [
	"ham_t.core.doctype.activity_log.feed.login_feed",
	"ham_t.core.doctype.user.user.notify_admin_access_to_system_manager",
]

on_logout = (
	"ham_t.core.doctype.session_default_settings.session_default_settings.clear_session_defaults"
)

# permissions

permission_query_conditions = {
	"Event": "ham_t.desk.doctype.event.event.get_permission_query_conditions",
	"ToDo": "ham_t.desk.doctype.todo.todo.get_permission_query_conditions",
	"User": "ham_t.core.doctype.user.user.get_permission_query_conditions",
	"Dashboard Settings": "ham_t.desk.doctype.dashboard_settings.dashboard_settings.get_permission_query_conditions",
	"Notification Log": "ham_t.desk.doctype.notification_log.notification_log.get_permission_query_conditions",
	"Dashboard": "ham_t.desk.doctype.dashboard.dashboard.get_permission_query_conditions",
	"Dashboard Chart": "ham_t.desk.doctype.dashboard_chart.dashboard_chart.get_permission_query_conditions",
	"Number Card": "ham_t.desk.doctype.number_card.number_card.get_permission_query_conditions",
	"Notification Settings": "ham_t.desk.doctype.notification_settings.notification_settings.get_permission_query_conditions",
	"Note": "ham_t.desk.doctype.note.note.get_permission_query_conditions",
	"Kanban Board": "ham_t.desk.doctype.kanban_board.kanban_board.get_permission_query_conditions",
	"Contact": "ham_t.contacts.address_and_contact.get_permission_query_conditions_for_contact",
	"Address": "ham_t.contacts.address_and_contact.get_permission_query_conditions_for_address",
	"Communication": "ham_t.core.doctype.communication.communication.get_permission_query_conditions_for_communication",
	"Workflow Action": "ham_t.workflow.doctype.workflow_action.workflow_action.get_permission_query_conditions",
	"Prepared Report": "ham_t.core.doctype.prepared_report.prepared_report.get_permission_query_condition",
}

has_permission = {
	"Event": "ham_t.desk.doctype.event.event.has_permission",
	"ToDo": "ham_t.desk.doctype.todo.todo.has_permission",
	"User": "ham_t.core.doctype.user.user.has_permission",
	"Note": "ham_t.desk.doctype.note.note.has_permission",
	"Dashboard Chart": "ham_t.desk.doctype.dashboard_chart.dashboard_chart.has_permission",
	"Number Card": "ham_t.desk.doctype.number_card.number_card.has_permission",
	"Kanban Board": "ham_t.desk.doctype.kanban_board.kanban_board.has_permission",
	"Contact": "ham_t.contacts.address_and_contact.has_permission",
	"Address": "ham_t.contacts.address_and_contact.has_permission",
	"Communication": "ham_t.core.doctype.communication.communication.has_permission",
	"Workflow Action": "ham_t.workflow.doctype.workflow_action.workflow_action.has_permission",
	"File": "ham_t.core.doctype.file.file.has_permission",
	"Prepared Report": "ham_t.core.doctype.prepared_report.prepared_report.has_permission",
}

has_website_permission = {
	"Address": "ham_t.contacts.doctype.address.address.has_website_permission"
}

jinja = {
	"methods": "ham_t.utils.jinja_globals",
	"filters": [
		"ham_t.utils.data.global_date_format",
		"ham_t.utils.markdown",
		"ham_t.website.utils.get_shade",
		"ham_t.website.utils.abs_url",
	],
}

standard_queries = {"User": "ham_t.core.doctype.user.user.user_query"}

doc_events = {
	"*": {
		"on_update": [
			"ham_t.desk.notifications.clear_doctype_notifications",
			"ham_t.core.doctype.activity_log.feed.update_feed",
			"ham_t.workflow.doctype.workflow_action.workflow_action.process_workflow_actions",
			"ham_t.automation.doctype.assignment_rule.assignment_rule.apply",
			"ham_t.core.doctype.file.utils.attach_files_to_document",
			"ham_t.automation.doctype.assignment_rule.assignment_rule.update_due_date",
			"ham_t.core.doctype.user_type.user_type.apply_permissions_for_non_standard_user_type",
		],
		"after_rename": "ham_t.desk.notifications.clear_doctype_notifications",
		"on_cancel": [
			"ham_t.desk.notifications.clear_doctype_notifications",
			"ham_t.workflow.doctype.workflow_action.workflow_action.process_workflow_actions",
		],
		"on_trash": [
			"ham_t.desk.notifications.clear_doctype_notifications",
			"ham_t.workflow.doctype.workflow_action.workflow_action.process_workflow_actions",
		],
		"on_update_after_submit": [
			"ham_t.workflow.doctype.workflow_action.workflow_action.process_workflow_actions"
		],
		"on_change": [
			"ham_t.social.doctype.energy_point_rule.energy_point_rule.process_energy_points",
			"ham_t.automation.doctype.milestone_tracker.milestone_tracker.evaluate_milestone",
		],
	},
	"Event": {
		"after_insert": "ham_t.integrations.doctype.google_calendar.google_calendar.insert_event_in_google_calendar",
		"on_update": "ham_t.integrations.doctype.google_calendar.google_calendar.update_event_in_google_calendar",
		"on_trash": "ham_t.integrations.doctype.google_calendar.google_calendar.delete_event_from_google_calendar",
	},
	"Contact": {
		"after_insert": "ham_t.integrations.doctype.google_contacts.google_contacts.insert_contacts_to_google_contacts",
		"on_update": "ham_t.integrations.doctype.google_contacts.google_contacts.update_contacts_to_google_contacts",
	},
	"DocType": {
		"on_update": "ham_t.cache_manager.build_domain_restriced_doctype_cache",
	},
	"Page": {
		"on_update": "ham_t.cache_manager.build_domain_restriced_page_cache",
	},
}

scheduler_events = {
	"cron": {
		"0/15 * * * *": [
			"ham_t.oauth.delete_oauth2_data",
			"ham_t.website.doctype.web_page.web_page.check_publish_status",
			"ham_t.twofactor.delete_all_barcodes_for_users",
		]
	},
	"all": [
		"ham_t.email.queue.flush",
		"ham_t.email.doctype.email_account.email_account.pull",
		"ham_t.email.doctype.email_account.email_account.notify_unreplied",
		"ham_t.utils.global_search.sync_global_search",
		"ham_t.monitor.flush",
	],
	"hourly": [
		"ham_t.model.utils.link_count.update_link_count",
		"ham_t.model.utils.user_settings.sync_user_settings",
		"ham_t.utils.error.collect_error_snapshots",
		"ham_t.desk.page.backups.backups.delete_downloadable_backups",
		"ham_t.deferred_insert.save_to_db",
		"ham_t.desk.form.document_follow.send_hourly_updates",
		"ham_t.integrations.doctype.google_calendar.google_calendar.sync",
		"ham_t.email.doctype.newsletter.newsletter.send_scheduled_email",
		"ham_t.website.doctype.personal_data_deletion_request.personal_data_deletion_request.process_data_deletion_request",
	],
	"daily": [
		"ham_t.email.queue.set_expiry_for_email_queue",
		"ham_t.desk.notifications.clear_notifications",
		"ham_t.desk.doctype.event.event.send_event_digest",
		"ham_t.sessions.clear_expired_sessions",
		"ham_t.email.doctype.notification.notification.trigger_daily_alerts",
		"ham_t.website.doctype.personal_data_deletion_request.personal_data_deletion_request.remove_unverified_record",
		"ham_t.desk.form.document_follow.send_daily_updates",
		"ham_t.social.doctype.energy_point_settings.energy_point_settings.allocate_review_points",
		"ham_t.integrations.doctype.google_contacts.google_contacts.sync",
		"ham_t.automation.doctype.auto_repeat.auto_repeat.make_auto_repeat_entry",
		"ham_t.automation.doctype.auto_repeat.auto_repeat.set_auto_repeat_as_completed",
		"ham_t.email.doctype.unhandled_email.unhandled_email.remove_old_unhandled_emails",
		"ham_t.core.doctype.prepared_report.prepared_report.delete_expired_prepared_reports",
		"ham_t.core.doctype.log_settings.log_settings.run_log_clean_up",
		"ham_t.utils.subscription.enable_manage_subscription",
	],
	"daily_long": [
		"ham_t.integrations.doctype.dropbox_settings.dropbox_settings.take_backups_daily",
		"ham_t.utils.change_log.check_for_update",
		"ham_t.integrations.doctype.s3_backup_settings.s3_backup_settings.take_backups_daily",
		"ham_t.email.doctype.auto_email_report.auto_email_report.send_daily",
		"ham_t.integrations.doctype.google_drive.google_drive.daily_backup",
	],
	"weekly_long": [
		"ham_t.integrations.doctype.dropbox_settings.dropbox_settings.take_backups_weekly",
		"ham_t.integrations.doctype.s3_backup_settings.s3_backup_settings.take_backups_weekly",
		"ham_t.desk.form.document_follow.send_weekly_updates",
		"ham_t.social.doctype.energy_point_log.energy_point_log.send_weekly_summary",
		"ham_t.integrations.doctype.google_drive.google_drive.weekly_backup",
	],
	"monthly": [
		"ham_t.email.doctype.auto_email_report.auto_email_report.send_monthly",
		"ham_t.social.doctype.energy_point_log.energy_point_log.send_monthly_summary",
	],
	"monthly_long": [
		"ham_t.integrations.doctype.s3_backup_settings.s3_backup_settings.take_backups_monthly"
	],
}

get_translated_dict = {
	("doctype", "System Settings"): "ham_t.geo.country_info.get_translated_dict",
	("page", "setup-wizard"): "ham_t.geo.country_info.get_translated_dict",
}

sounds = [
	{"name": "email", "src": "/assets/ham_t/sounds/email.mp3", "volume": 0.1},
	{"name": "submit", "src": "/assets/ham_t/sounds/submit.mp3", "volume": 0.1},
	{"name": "cancel", "src": "/assets/ham_t/sounds/cancel.mp3", "volume": 0.1},
	{"name": "delete", "src": "/assets/ham_t/sounds/delete.mp3", "volume": 0.05},
	{"name": "click", "src": "/assets/ham_t/sounds/click.mp3", "volume": 0.05},
	{"name": "error", "src": "/assets/ham_t/sounds/error.mp3", "volume": 0.1},
	{"name": "alert", "src": "/assets/ham_t/sounds/alert.mp3", "volume": 0.2},
	# {"name": "chime", "src": "/assets/ham_t/sounds/chime.mp3"},
]

setup_wizard_exception = [
	"ham_t.desk.page.setup_wizard.setup_wizard.email_setup_wizard_exception",
	"ham_t.desk.page.setup_wizard.setup_wizard.log_setup_wizard_exception",
]

before_migrate = []
after_migrate = ["ham_t.website.doctype.website_theme.website_theme.after_migrate"]

otp_methods = ["OTP App", "Email", "SMS"]

user_data_fields = [
	{"doctype": "Access Log", "strict": True},
	{"doctype": "Activity Log", "strict": True},
	{"doctype": "Comment", "strict": True},
	{
		"doctype": "Contact",
		"filter_by": "email_id",
		"redact_fields": ["first_name", "last_name", "phone", "mobile_no"],
		"rename": True,
	},
	{"doctype": "Contact Email", "filter_by": "email_id"},
	{
		"doctype": "Address",
		"filter_by": "email_id",
		"redact_fields": [
			"address_title",
			"address_line1",
			"address_line2",
			"city",
			"county",
			"state",
			"pincode",
			"phone",
			"fax",
		],
	},
	{
		"doctype": "Communication",
		"filter_by": "sender",
		"redact_fields": ["sender_full_name", "phone_no", "content"],
	},
	{"doctype": "Communication", "filter_by": "recipients"},
	{"doctype": "Email Group Member", "filter_by": "email"},
	{"doctype": "Email Unsubscribe", "filter_by": "email", "partial": True},
	{"doctype": "Email Queue", "filter_by": "sender"},
	{"doctype": "Email Queue Recipient", "filter_by": "recipient"},
	{
		"doctype": "File",
		"filter_by": "attached_to_name",
		"redact_fields": ["file_name", "file_url"],
	},
	{
		"doctype": "User",
		"filter_by": "name",
		"redact_fields": [
			"email",
			"username",
			"first_name",
			"middle_name",
			"last_name",
			"full_name",
			"birth_date",
			"user_image",
			"phone",
			"mobile_no",
			"location",
			"banner_image",
			"interest",
			"bio",
			"email_signature",
		],
	},
	{"doctype": "Version", "strict": True},
]

global_search_doctypes = {
	"Default": [
		{"doctype": "Contact"},
		{"doctype": "Address"},
		{"doctype": "ToDo"},
		{"doctype": "Note"},
		{"doctype": "Event"},
		{"doctype": "Blog Post"},
		{"doctype": "Dashboard"},
		{"doctype": "Country"},
		{"doctype": "Currency"},
		{"doctype": "Newsletter"},
		{"doctype": "Letter Head"},
		{"doctype": "Workflow"},
		{"doctype": "Web Page"},
		{"doctype": "Web Form"},
	]
}

override_whitelisted_methods = {
	"ham_t.core.doctype.file.file.download_file": "download_file",
	"ham_t.core.doctype.file.file.unzip_file": "ham_t.core.api.file.unzip_file",
	"ham_t.core.doctype.file.file.get_attached_images": "ham_t.core.api.file.get_attached_images",
	"ham_t.core.doctype.file.file.get_files_in_folder": "ham_t.core.api.file.get_files_in_folder",
	"ham_t.core.doctype.file.file.get_files_by_search_text": "ham_t.core.api.file.get_files_by_search_text",
	"ham_t.core.doctype.file.file.get_max_file_size": "ham_t.core.api.file.get_max_file_size",
	"ham_t.core.doctype.file.file.create_new_folder": "ham_t.core.api.file.create_new_folder",
	"ham_t.core.doctype.file.file.move_file": "ham_t.core.api.file.move_file",
	"ham_t.core.doctype.file.file.zip_files": "ham_t.core.api.file.zip_files",
}
