from datetime import time, timedelta, datetime

WORK_START = time(8, 0, 0)
WORK_END = time(17, 0, 0)

def calculate_lateness(logs):
    checkins = [log for log in logs if log.action == 'checkin']
    if not checkins:
        return timedelta(0)
    first_checkin = min(checkins, key=lambda l: l.timestamp)
    lateness = datetime.combine(first_checkin.timestamp.date(), first_checkin.timestamp.time()) - datetime.combine(first_checkin.timestamp.date(), WORK_START)
    return max(timedelta(0), lateness)

def calculate_early_leave(logs):
    checkouts = [log for log in logs if log.action == 'checkout']
    if not checkouts:
        return timedelta(0)
    last_checkout = max(checkouts, key=lambda l: l.timestamp)
    early_leave = datetime.combine(last_checkout.timestamp.date(), WORK_END) - datetime.combine(last_checkout.timestamp.date(), last_checkout.timestamp.time())
    return max(timedelta(0), early_leave)
