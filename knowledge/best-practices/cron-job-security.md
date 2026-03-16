# Cron Job Security

## DO

- **Authenticate cron triggers**. If cron jobs are triggered via HTTP endpoints, require an auth token or restrict to internal network. Never expose cron endpoints publicly.
- **Make handlers idempotent**. Cron jobs may run twice (overlapping executions, retries). Use database locks or deduplication to prevent double-processing.
- **Use distributed locks** (Redis SETNX, database advisory locks) to prevent concurrent execution of the same job across multiple instances.
- **Set execution timeouts**. Kill jobs that exceed the expected duration — hung jobs block subsequent runs and leak resources.
- **Rotate secrets used by cron jobs** on the same schedule as other credentials. Cron-specific service accounts should have minimal permissions.
- **Alert on failures immediately**. Cron jobs fail silently by default. Send alerts to a monitored channel (PagerDuty, Slack, email) on any non-zero exit.
- **Log start time, end time, items processed, and errors** for every run. This is your audit trail and debugging lifeline.
- **Run with least-privilege permissions**. A cron job that sends emails doesn't need database write access.

```bash
# Lock file pattern to prevent overlapping runs
LOCKFILE="/tmp/my-job.lock"
exec 200>"$LOCKFILE"
flock -n 200 || { echo "Already running"; exit 0; }
# ... job logic here ...
```

## DON'T

- Expose cron endpoints without authentication. `/api/cron/cleanup` with no auth means anyone can trigger your jobs.
- Hardcode secrets in crontab entries or shell scripts. Use environment variables from a secrets manager.
- Run cron jobs as root. Use a dedicated service account with minimal permissions.
- Ignore exit codes. A cron job that fails silently will corrupt data for days before anyone notices.
- Skip logging because "it's just a background job." Cron jobs are harder to debug than request handlers.
- Store cron schedules in user-controllable configuration without validation — cron expression injection can cause resource exhaustion.

## Common AI Mistakes

- Creating an unauthenticated `/api/cron/daily-cleanup` endpoint and relying on "nobody will find it."
- Not implementing any locking, causing two instances of the same job to run simultaneously and corrupt shared state.
- Hardcoding database passwords in the cron script instead of using environment variables or secrets manager.
- Setting a cron job to run every minute during development and forgetting to change it in production.
- Not setting a timeout — a stuck database query makes the cron job hang forever, blocking future runs.
- Logging the full payload including sensitive user data instead of just job metadata.
