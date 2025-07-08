# scheduler.py
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
from whatsapp_client import client as whatsapp_client
import config

# Use a timezone-aware scheduler
israel_tz = pytz.timezone('Asia/Jerusalem')
scheduler = BackgroundScheduler(timezone=israel_tz)

def sync_message_to_all_groups(original_message):
    """The job that the scheduler will execute."""
    logging.info(f"⏰ EXECUTING SCHEDULED JOB: Syncing message to {len(config.TARGET_GROUP_IDS)} groups.")
    if not config.TARGET_GROUP_IDS:
        logging.warning("Scheduler fired, but no target groups are defined.")
        return

    for group_id in config.TARGET_GROUP_IDS:
        whatsapp_client.resend_message(group_id, original_message)

    whatsapp_client.send_text_message(
        config.OWNER_PHONE_NUMBER,
        "✅ Your scheduled message has been successfully sent to all groups!"
    )

def schedule_sync(run_date: datetime, original_message: dict):
    """Adds a sync job to the scheduler."""
    job_id = f"sync_{original_message.get('id', 'N/A')}"
    scheduler.add_job(
        sync_message_to_all_groups,
        'date',
        run_date=run_date,
        args=[original_message],
        id=job_id,
        replace_existing=True
    )
    logging.info(f"✅ Job '{job_id}' scheduled for {run_date.strftime('%Y-%m-%d %H:%M:%S %Z')}")

def start_scheduler():
    """Starts the background scheduler."""
    if not scheduler.running:
        scheduler.start()
        logging.info("⏰ Background scheduler started.")