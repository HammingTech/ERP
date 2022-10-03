"""docfield utililtes"""

import ham_t


def rename(doctype, fieldname, newname):
	"""rename docfield"""
	df = ham_t.db.sql(
		"""select * from tabDocField where parent=%s and fieldname=%s""", (doctype, fieldname), as_dict=1
	)
	if not df:
		return

	df = df[0]

	if ham_t.db.get_value("DocType", doctype, "issingle"):
		update_single(df, newname)
	else:
		update_table(df, newname)
		update_parent_field(df, newname)


def update_single(f, new):
	"""update in tabSingles"""
	ham_t.db.begin()
	ham_t.db.sql(
		"""update tabSingles set field=%s where doctype=%s and field=%s""",
		(new, f["parent"], f["fieldname"]),
	)
	ham_t.db.commit()


def update_table(f, new):
	"""update table"""
	query = get_change_column_query(f, new)
	if query:
		ham_t.db.sql(query)


def update_parent_field(f, new):
	"""update 'parentfield' in tables"""
	if f["fieldtype"] in ham_t.model.table_fields:
		ham_t.db.begin()
		ham_t.db.sql(
			"""update `tab{}` set parentfield={} where parentfield={}""".format(f["options"], "%s", "%s"),
			(new, f["fieldname"]),
		)
		ham_t.db.commit()


def get_change_column_query(f, new):
	"""generate change fieldname query"""
	desc = ham_t.db.sql("desc `tab%s`" % f["parent"])
	for d in desc:
		if d[0] == f["fieldname"]:
			return "alter table `tab{}` change `{}` `{}` {}".format(f["parent"], f["fieldname"], new, d[1])


def supports_translation(fieldtype):
	return fieldtype in ["Data", "Select", "Text", "Small Text", "Text Editor"]
