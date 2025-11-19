import random
import string
import json
from datetime import datetime
from zoneinfo import ZoneInfo

def generate_auid():
    # 7 alphanumeric
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))

def generate_cuid():
    # 8 alphanumeric
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def generate_order_id():
    return "SVSCO" + ''.join(random.choices(string.digits, k=6))

def generate_bill_id():
    return "SVSB" + ''.join(random.choices(string.digits, k=6))

def now_str():
    ist_time = datetime.now(ZoneInfo("Asia/Kolkata"))
    return ist_time.strftime("%Y-%m-%d %H:%M:%S")

def items_to_json(item_list):
    """
    item_list expected as list of dicts: [{"name": "Rice", "qty": "2kg", "price": 120}, ...]
    """
    return json.dumps(item_list)

def items_from_json(json_text):
    import json
    if not json_text:
        return []
    try:
        return json.loads(json_text)
    except:
        return []
