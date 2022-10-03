# Copyright (c) 2015, ham_t Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE

# Database Module
# --------------------

from ham_t.database.database import savepoint


def setup_database(force, source_sql=None, verbose=None, no_mariadb_socket=False):
	import ham_t

	if ham_t.conf.db_type == "postgres":
		import ham_t.database.postgres.setup_db

		return ham_t.database.postgres.setup_db.setup_database(force, source_sql, verbose)
	else:
		import ham_t.database.mariadb.setup_db

		return ham_t.database.mariadb.setup_db.setup_database(
			force, source_sql, verbose, no_mariadb_socket=no_mariadb_socket
		)


def drop_user_and_database(db_name, root_login=None, root_password=None):
	import ham_t

	if ham_t.conf.db_type == "postgres":
		import ham_t.database.postgres.setup_db

		return ham_t.database.postgres.setup_db.drop_user_and_database(
			db_name, root_login, root_password
		)
	else:
		import ham_t.database.mariadb.setup_db

		return ham_t.database.mariadb.setup_db.drop_user_and_database(
			db_name, root_login, root_password
		)


def get_db(host=None, user=None, password=None, port=None):
	import ham_t

	if ham_t.conf.db_type == "postgres":
		import ham_t.database.postgres.database

		return ham_t.database.postgres.database.PostgresDatabase(host, user, password, port=port)
	else:
		import ham_t.database.mariadb.database

		return ham_t.database.mariadb.database.MariaDBDatabase(host, user, password, port=port)
