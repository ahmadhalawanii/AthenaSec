# Migrations

Hand-written raw SQL, PostgreSQL only. SQLAlchemy is installed because Alembic requires it;
no ORM models are used. Migrations create empty tables and never insert rows.

```
export ATHENASEC_DATABASE_URL=postgresql://user:pass@host:5432/db   # from agent/

# New, empty database: builds the whole schema
alembic upgrade head

# Existing database that the stores already created: record the baseline, run nothing
alembic stamp 0001
alembic upgrade head          # applies only revisions after 0001

alembic current               # show the recorded revision
alembic upgrade head --sql    # print the SQL without a database
```

`0001` is the schema the store constructors create today (idempotent `IF NOT EXISTS`). The
constructors still run on startup and are untouched. New objects (from `0002`) live only here.
SQLite (dev and tests) is not managed by Alembic.
