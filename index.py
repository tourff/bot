import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say


#EMOTES BY  TURJO 
# FIXED BY  TURJO 


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# VariabLes dyli 
#------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
#------------------------------------------#

# ----------------- NEW GLOBAL CONFIG / STATE -----------------
# Admin list (UID ints) — কাস্টমাইজ করো
ADMIN_UIDS = {2172143722}

# Cooldown infra: dict of (uid, cmd) -> last_ts
_command_cooldowns = {}  # key: (uid, cmd) value: ts
DEFAULT_COOLDOWNS = {
    '/help': 2,
    '/profile': 3,
    '/claninfo': 3,
    '/guildinfo': 3,
    '/announce': 5,
    '/burst': 60,
    '/slowmode': 2,
    '/fastburst-sim': 5,
}

# Slowmode (group level)
SLOWMODE_ENABLED = False
SLOWMODE_INTERVAL = 10        # seconds default
_slowmode_last = {}           # chat_id -> {uid -> last_ts}
SLOWMODE_ADMINS = set(ADMIN_UIDS)

# Emote burst settings (controlled)
EMOTE_BURST_MAX = 5            # সর্বোচ্চ এমোট সংখ্যা একবারে
EMOTE_BURST_MIN_DELAY = 1.0    # ন্যূনতম delay (s)
EMOTE_BURST_COOLDOWN = 60      # প্রতি admin cooldown (s)
_emote_burst_cooldowns = {}    # admin_uid -> last_ts

# Dry-run flag (optional)
DRY_RUN = False

# ------------------------------------------------------------

####################################

# --- Updated Get_clan_info: show "GUILD INFO" heading ---
def Get_clan_info(clan_id):
    try:
        url = f"https://get-clan-info.vercel.app/get_clan_info?clan_id={clan_id}"
        res = requests.get(url)
        if res.status_code == 200:
            data = res.json()
            msg = f""" 
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
▶▶▶▶ GUILD INFO ◀◀◀◀
Achievements: {data.get('achievements')}\n\n
Balance : {fix_num(data.get('balance',0))}\n\n
Guild/Clan Name : {data.get('clan_name')}\n\n
Expire Time : {fix_num(data.get('guild_details',{}).get('expire_time',0))}\n\n
Members Online : {fix_num(data.get('guild_details',{}).get('members_online',0))}\n\n
Regional : {data.get('guild_details',{}).get('regional')}\n\n
Reward Time : {fix_num(data.get('guild_details',{}).get('reward_time',0))}\n\n
Total Members : {fix_num(data.get('guild_details',{}).get('total_members',0))}\n\n
ID : {fix_num(data.get('id',0))}\n\n
Last Active : {fix_num(data.get('last_active',0))}\n\n
Level : {fix_num(data.get('level',0))}\n\n
Rank : {fix_num(data.get('rank',0))}\n\n
Region : {data.get('region')}\n\n
Score : {fix_num(data.get('score',0))}\n\n
Timestamp1 : {fix_num(data.get('timestamp1',0))}\n\n
Timestamp2 : {fix_num(data.get('timestamp2',0))}\n\n
Welcome Message: {data.get('welcome_message')}\n\n
XP: {fix_num(data.get('xp',0))}\n\n
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY ALAMINgaming.90
            """
            return msg
        else:
            msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Failed to get guild info, please try again later!!

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY TURJO 
            """
            return msg
    except Exception as e:
        print("Get_clan_info error:", e)
        return "[FF0000]Error fetching guild info."

#GET INFO BY PLAYER ID
def get_player_info(player_id):
    url = f"https://like2.vercel.app/player-info?uid={player_id}&server={server2}&key={key2}"
    response = requests.get(url)
    print(response)    
    if response.status_code == 200:
        try:
            r = response.json()
            return {
                "Account Booyah Pass": f"{r.get('booyah_pass_level', 'N/A')}",
                "Account Create": f"{r.get('createAt', 'N/A')}",
                "Account Level": f"{r.get('level', 'N/A')}",
                "Account Likes": f" {r.get('likes', 'N/A')}",
                "Name": f"{r.get('nickname', 'N/A')}",
                "UID": f" {r.get('accountId', 'N/A')}",
                "Account Region": f"{r.get('region', 'N/A')}",
                }
        except ValueError as e:
            pass
            return {
                "error": "Invalid JSON response"
            }
    else:
        pass
        return {
            "error": f"Failed to fetch data: {response.status_code}"
        }
#CHAT WITH AI
def talk_with_ai(question):
    url = f"https://gemini-api-api-v2.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    res = requests.get(url)
    if res.status_code == 200:
        data = res.json()
        msg = data["message"]["content"]
        return msg
    else:
        return "An error occurred while connecting to the server."
#SPAM REQUESTS
def spam_requests(player_id):
    # This URL now correctly points to the Flask app you provided
    url = f"https://like2.vercel.app/send_requests?uid={player_id}&server={server2}&key={key2}"
    try:
        res = requests.get(url, timeout=20) # Added a timeout
        if res.status_code == 200:
            data = res.json()
            # Return a more descriptive message based on the API's JSON response
            return f"API Status: Success [{data.get('success_count', 0)}] Failed [{data.get('failed_count', 0)}]"
        else:
            # Return the error status from the API
            return f"API Error: Status {res.status_code}"
    except requests.exceptions.RequestException as e:
        # Handle cases where the API isn't running or is unreachable
        print(f"Could not connect to spam API: {e}")
        return "Failed to connect to spam API."
####################################

# ** NEW INFO FUNCTION using the new API **
def newinfo(uid):
    # Base URL without parameters
    url = "https://like2.vercel.app/player-info"
    # Parameters dictionary - this is the robust way to do it
    params = {
        'uid': uid,
        'server': server2,  # Hardcoded to bd as requested
        'key': key2
    }
    try:
        # Pass the parameters to requests.get()
        response = requests.get(url, params=params, timeout=10)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            # Check if the expected data structure is in the response
            if "basicInfo" in data:
                return {"status": "ok", "data": data}
            else:
                # The API returned 200, but the data is not what we expect (e.g., error message in JSON)
                return {"status": "error", "message": data.get("error", "Invalid ID or data not found.")}
        else:
            # The API returned an error status code (e.g., 404, 500)
            try:
                # Try to get a specific error message from the API's response
                error_msg = response.json().get('error', f"API returned status {response.status_code}")
                return {"status": "error", "message": error_msg}
            except ValueError:
                # If the error response is not JSON
                return {"status": "error", "message": f"API returned status {response.status_code}"}

    except requests.exceptions.RequestException as e:
        # Handle network errors (e.g., timeout, no connection)
        return {"status": "error", "message": f"Network error: {str(e)}"}
    except ValueError: 
        # Handle cases where the response is not valid JSON
        return {"status": "error", "message": "Invalid JSON response from API."}

	
#ADDING-100-LIKES-IN-24H
def send_likes(uid):
    try:
        likes_api_response = requests.get(
             f"https://yourlikeapi?uid={uid}&server_name={server2}&x-vercel-set-bypass-cookie=true&x-vercel-protection-bypass={BYPASS_TOKEN}",
             timeout=15
             )
      
      
        if likes_api_response.status_code != 200:
            return f"""
[C][B][FF0000]━━━━━
[FFFFFF]Like API Error!
Status Code: {likes_api_response.status_code}
Please check if the uid is correct.
━━━━━
"""

        api_json_response = likes_api_response.json()

        player_name = api_json_response.get('PlayerNickname', 'Unknown')
        likes_before = api_json_response.get('LikesbeforeCommand', 0)
        likes_after = api_json_response.get('LikesafterCommand', 0)
        likes_added = api_json_response.get('LikesGivenByAPI', 0)
        status = api_json_response.get('status', 0)

        if status == 1 and likes_added > 0:
            # ✅ Success
            return f"""
[C][B][11EAFD]‎━━━━━━━━━━━━
[FFFFFF]Likes Status:

[00FF00]Likes Sent Successfully!

[FFFFFF]Player Name : [00FF00]{player_name}  
[FFFFFF]Likes Added : [00FF00]{likes_added}  
[FFFFFF]Likes Before : [00FF00]{likes_before}  
[FFFFFF]Likes After : [00FF00]{likes_after}  
[C][B][11EAFD]‎━━━━━━━━━━━━
[C][B][FFB300]Subscribe: [FFFFFF] ALAMIN [00FF00]!!
"""
        elif status == 2 or likes_before == likes_after:
            # 🚫 Already claimed / Maxed
            return f"""
[C][B][FF0000]━━━━━━━━━━━━

[FFFFFF]No Likes Sent!

[FF0000]You have already taken likes with this UID.
Try again after 24 hours.

[FFFFFF]Player Name : [FF0000]{player_name}  
[FFFFFF]Likes Before : [FF0000]{likes_before}  
[FFFFFF]Likes After : [FF0000]{likes_after}  
[C][B][FF0000]━━━━━━━━━━━━
"""
        else:
            # ❓ Unexpected case
            return f"""
[C][B][FF0000]━━━━━━━━━━━━
[FFFFFF]Unexpected Response!
Something went wrong.

Please try again or contact support.
━━━━━━━━━━━━
"""

    except requests.exceptions.RequestException:
        return """
[C][B][FF0000]━━━━━
[FFFFFF]Like API Connection Failed!
Is the API server (app.py) running?
━━━━━
"""
    except Exception as e:
        return f"""
[C][B][FF0000]━━━━━
[FFFFFF]An unexpected error occurred:
[FF0000]{str(e)}
━━━━━
"""
####################################
#CHECK ACCOUNT IS BANNED

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"}

# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

# ----------------- Helper functions for new features -----------------
def is_admin(uid):
    try:
        return int(uid) in ADMIN_UIDS
    except:
        return False

def check_cooldown(uid, cmd):
    key = (int(uid), cmd)
    last = _command_cooldowns.get(key, 0)
    cd = DEFAULT_COOLDOWNS.get(cmd, 2)
    now = time.time()
    if now - last < cd:
        return False, int(cd - (now - last))
    return True, 0

def set_cooldown(uid, cmd):
    key = (int(uid), cmd)
    _command_cooldowns[key] = time.time()

async def send_text_message(chat_type, message, uid, chat_id, key, iv):
    # wrapper to build and send a text message using existing SEndMsG/SEndPacKeT
    try:
        P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
    except Exception as e:
        print("send_text_message error:", e)

# --------------------------------------------------------------------

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
    elif TypE == 'OnLine': online_writer.write(PacKeT) ; await online_writer.drain()
    else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 
           
async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer , spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , XX , uid , Spy,data2, Chat_Leave
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        print(data2.hex()[10:])
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        print(packet)
                        packet = json.loads(packet)
                        OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT)


                        message = f'[B][C][FFD700][b][c]\n"[00FF00]🤖  ALAMIN BOT[c]\n[FFFFFF]🚀 Bot Working Now [c]\n[00BFFF]👤 Welcome to the bot![c]\n[FFFFFF]✨ Type /help to see commands[c]\n[FF69B4]⚡ Safe & Legit Gaming Assistant[c] '
                        P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)

                    except:
                        if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                            try:
                                print(data2.hex()[10:])
                                packet = await DeCode_PackEt(data2.hex()[10:])
                                print(packet)
                                packet = json.loads(packet)
                                OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                                JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT)


                                message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! \n\n{get_random_color()}- Commands : @a {xMsGFixinG('player_uid')} {xMsGFixinG('909000001')}\n\n[00FF00]Dev : @{xMsGFixinG(' ALAMIN')}'
                                P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                            except:
                                pass

            online_writer.close() ; await online_writer.wait_closed() ; online_writer = None

        except Exception as e: print(f"- ErroR With {ip}:{port} - {e}") ; online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , reconnect_delay=0.5):
    print(region, 'TCP CHAT')

    global spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , online_writer , chat_id , XX , uid , Spy,data2, Chat_Leave
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if whisper_writer: whisper_writer.write(pK) ; await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):

                    msg = await DeCode_PackEt(data.hex()[10:])
                    chatdata = json.loads(msg)
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()
                    except:
                        response = None


                    if response:
                        # --- SLOWMODE ENFORCEMENT (applies to group chats only) ---
                        if SLOWMODE_ENABLED and response.Data.chat_type in (0,1):
                            now = time.time()
                            chat_map = _slowmode_last.setdefault(chat_id, {})
                            last = chat_map.get(response.Data.uid, 0)
                            if now - last < SLOWMODE_INTERVAL:
                                wait = int(SLOWMODE_INTERVAL - (now - last))
                                warn = f"[FF0000]Slowmode active. Please wait {wait}s before sending again."
                                P = await SEndMsG(response.Data.chat_type, warn, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                # skip processing this message
                                continue
                            else:
                                chat_map[response.Data.uid] = now

                        # basic cooldown check for simple commands (per user)
                        # check for help/profile/claninfo etc.
                        if inPuTMsG.strip().split():
                            base_cmd = inPuTMsG.strip().split()[0]
                        else:
                            base_cmd = ''

                        # If command has cooldown, enforce it
                        if base_cmd in DEFAULT_COOLDOWNS:
                            ok, wait = check_cooldown(response.Data.uid, base_cmd)
                            if not ok:
                                msg = f"[FF0000]Please wait {wait}s before using {base_cmd} again."
                                P = await SEndMsG(response.Data.chat_type, msg, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            else:
                                set_cooldown(response.Data.uid, base_cmd)

                        # /help handler (improved)
                        if inPuTMsG in ("hi" , "/help" , "start" , "help") or inPuTMsG.startswith('/help '):
                            uid = response.Data.uid
                            chat_id = response.Data.Chat_ID
                            # improved help template
                            help_msg = (
                                "[FF2400][b][c]✨  TURJO HACKER ✨[c]\n"
                                "[FFFFFF]━━━━━━━━━━━━━━━━━━━━[c]\n"
                                "[00FF00]🎮 ⚡EMOTE COMMANDS⚡:[c]\n"
                                "[FFFF00]@a [uid] [emote-id][c] - Perform Emote (group only)\n"
                                "[FFFF00]/x/ [team code][c] - Invite BOT\n"
                                "[FFFF00]/5[c] - 5 Player Squad (group)\n"
                                "[FFFF00]/solo[c] - Leave Squad\n"
                                "[FFFFFF]━━━━━━━━━━━━━━━━━━━━[c]\n"
                                "[00BFFF]🔍 ©️UTILITY:[c]\n"
                                "[FFFF00]/profile [uid][c] - Player Profile\n"
                                "[FFFF00]/guildinfo [clan_id][c] - Guild Info\n"
                                "[FFFF00]/announce [message][c] - Admin only: Post announcement\n"
                                "[FFFF00]/slowmode on/off [seconds][c] - Admin only: Toggle group slowmode\n"
                                "[FFFF00]/burst <uid> <emote_id> <count> <delay>[c] - Admin only: controlled emote burst\n"
                                "[FFFF00]/fastburst-sim <uid> <emote_id>[c] - Admin only: simulated fast 20x emote (text only)\n"
                                "[FFFFFF]━━━━━━━━━━━━━━━━━━━━[c]\n"
                                "[FF69B4]⚡ Safe & Legit Bot\n"
                                "[FF0000]নিয়ম:- [00FF00]প্রতি সপ্তাহে 1000 গ্লোরি না করলে গিল্ড থেকে কিক দেওয়া হবে\n"
                            )
                            P = await SEndMsG(response.Data.chat_type , help_msg , uid , chat_id , key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                            continue

                        # /profile handler -> uses newinfo()
                        if inPuTMsG.startswith('/profile'):
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2:
                                msg = "[FF0000]Usage: /profile <uid>"
                                await send_text_message(response.Data.chat_type, msg, uid, chat_id, key, iv)
                            else:
                                try:
                                    target_uid = parts[1]
                                    info = newinfo(target_uid)
                                    if isinstance(info, dict) and info.get('status') == 'ok':
                                        data = info['data']
                                        # format a simple profile summary (customize as you like)
                                        basic = data.get('basicInfo') or data
                                        name = basic.get('nickname', 'N/A') if isinstance(basic, dict) else 'N/A'
                                        level = basic.get('level', 'N/A') if isinstance(basic, dict) else basic.get('level','N/A')
                                        likes = basic.get('likes', 'N/A') if isinstance(basic, dict) else basic.get('likes','N/A')
                                        profile_msg = f"[00FF00]Player: {name}\n[FFFFFF]UID: {target_uid}\n[00BFFF]Level: {level}\n[FFFF00]Likes: {likes}"
                                        await send_text_message(response.Data.chat_type, profile_msg, uid, chat_id, key, iv)
                                    elif isinstance(info, dict) and info.get('status') == 'error':
                                        await send_text_message(response.Data.chat_type, f"[FF0000]{info.get('message')}", uid, chat_id, key, iv)
                                    else:
                                        await send_text_message(response.Data.chat_type, "[FF0000]Failed to fetch profile.", uid, chat_id, key, iv)
                                except Exception as e:
                                    print("profile error:", e)
                                    await send_text_message(response.Data.chat_type, "[FF0000]Error fetching profile.", uid, chat_id, key, iv)
                            continue

                        # /guildinfo or /claninfo handler
                        if inPuTMsG.startswith('/claninfo') or inPuTMsG.startswith('/guildinfo'):
                            parts = inPuTMsG.strip().split()
                            if len(parts) >= 2:
                                try:
                                    clan_id = parts[1]
                                    msg = Get_clan_info(clan_id)
                                    await send_text_message(response.Data.chat_type, msg, uid, chat_id, key, iv)
                                except Exception as e:
                                    print("clan/guild info error:", e)
                                    await send_text_message(response.Data.chat_type, "[FF0000]Error fetching guild info.", uid, chat_id, key, iv)
                            else:
                                # try using LoGinDaTaUncRypTinG.Clan_ID if present
                                try:
                                    if LoGinDaTaUncRypTinG and getattr(LoGinDaTaUncRypTinG, 'Clan_ID', None):
                                        clan_id = LoGinDaTaUncRypTinG.Clan_ID
                                        msg = Get_clan_info(clan_id)
                                        await send_text_message(response.Data.chat_type, msg, uid, chat_id, key, iv)
                                    else:
                                        await send_text_message(response.Data.chat_type, "[FF0000]Please specify a guild id: /guildinfo <id>", uid, chat_id, key, iv)
                                except Exception as e:
                                    print("claninfo fallback error:", e)
                                    await send_text_message(response.Data.chat_type, "[FF0000]Error fetching guild info.", uid, chat_id, key, iv)
                            continue

                        # /announce (admin only)
                        if inPuTMsG.startswith('/announce'):
                            caller = response.Data.uid
                            if not is_admin(caller):
                                await send_text_message(response.Data.chat_type, "[FF0000]Only admins can use /announce.", uid, chat_id, key, iv)
                            else:
                                parts = inPuTMsG.strip().split(maxsplit=1)
                                if len(parts) < 2:
                                    await send_text_message(response.Data.chat_type, "[FF0000]Usage: /announce <message>", uid, chat_id, key, iv)
                                else:
                                    ann = parts[1]
                                    # send announcement to clan (chat_type=1) if in clan, else to current chat
                                    target_chat_type = response.Data.chat_type if response.Data.chat_type in (0,1) else 1
                                    await send_text_message(target_chat_type, f"[FFB300][b][c]ANNOUNCEMENT:\n{ann}", uid, chat_id, key, iv)
                            continue

                        # /slowmode on/off [seconds] (admin)
                        if inPuTMsG.strip().startswith('/slowmode'):
                            caller = response.Data.uid
                            if not is_admin(caller):
                                await send_text_message(response.Data.chat_type, "[FF0000]Only admins can change slowmode.", uid, chat_id, key, iv)
                            else:
                                parts = inPuTMsG.strip().split()
                                if len(parts) >= 2 and parts[1].lower() == 'on':
                                    try:
                                        sec = int(parts[2]) if len(parts) >= 3 else SLOWMODE_INTERVAL
                                        # set global slowmode (could be extended to per-chat)
                                        globals()['SLOWMODE_INTERVAL'] = max(1, sec)
                                        globals()['SLOWMODE_ENABLED'] = True
                                        await send_text_message(response.Data.chat_type, f"[00FF00]Slowmode enabled: {SLOWMODE_INTERVAL}s per user.", uid, chat_id, key, iv)
                                    except Exception:
                                        await send_text_message(response.Data.chat_type, "[FF0000]Usage: /slowmode on <seconds>", uid, chat_id, key, iv)
                                elif len(parts) >= 2 and parts[1].lower() == 'off':
                                    globals()['SLOWMODE_ENABLED'] = False
                                    await send_text_message(response.Data.chat_type, "[00FF00]Slowmode disabled.", uid, chat_id, key, iv)
                                else:
                                    await send_text_message(response.Data.chat_type, "[FF0000]Usage: /slowmode on <seconds>  or  /slowmode off", uid, chat_id, key, iv)
                            continue

                        # /burst controlled emote burst (admin only)
                        if inPuTMsG.strip().startswith(('/burst', '/emoteburst')):
                            parts = inPuTMsG.strip().split()
                            caller_uid = response.Data.uid
                            if caller_uid not in ADMIN_UIDS:
                                await send_text_message(response.Data.chat_type, "[FF0000]Only admins can run /burst.", uid, chat_id, key, iv)
                                continue
                            if response.Data.chat_type == 2:
                                await send_text_message(response.Data.chat_type, "[FF0000]Use this command in Squad or Clan chat (not private).", uid, chat_id, key, iv)
                                continue
                            if len(parts) < 4:
                                await send_text_message(response.Data.chat_type, "[FF0000]Usage: /burst <target_uid> <emote_id> <count> <delay>", uid, chat_id, key, iv)
                                continue
                            try:
                                target_uid = int(parts[1])
                                emote_id = int(parts[2])
                                requested_count = int(parts[3])
                                delay = float(parts[4]) if len(parts) >= 5 else 1.0

                                count = min(max(1, requested_count), EMOTE_BURST_MAX)
                                delay = max(delay, EMOTE_BURST_MIN_DELAY)

                                now = time.time()
                                last = _emote_burst_cooldowns.get(caller_uid, 0)
                                if now - last < EMOTE_BURST_COOLDOWN:
                                    wait = int(EMOTE_BURST_COOLDOWN - (now - last))
                                    await send_text_message(response.Data.chat_type, f"[FF0000]Please wait {wait}s before running /burst again.", uid, chat_id, key, iv)
                                    continue
                                _emote_burst_cooldowns[caller_uid] = now
                                await send_text_message(response.Data.chat_type, f"[00FF00]Starting emote burst: {count}x emote {emote_id} to {target_uid} with {delay}s delay.", uid, chat_id, key, iv)

                                # perform burst but limited
                                for i in range(count):
                                    try:
                                        H = await Emote_k(target_uid, emote_id, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                    except Exception as e:
                                        print(f"Emote burst iteration error: {e}")
                                    await asyncio.sleep(delay)

                                await send_text_message(response.Data.chat_type, f"[00FF00]Emote burst completed ({count} times).", uid, chat_id, key, iv)
                            except ValueError:
                                await send_text_message(response.Data.chat_type, "[FF0000]Invalid arguments. UIDs and emote_id and count must be numbers.", uid, chat_id, key, iv)
                            except Exception as e:
                                print("Unexpected /burst error:", e)
                                await send_text_message(response.Data.chat_type, "[FF0000]An error occurred running /burst.", uid, chat_id, key, iv)
                            continue

                        # --- Safe simulated fast burst: /fastburst-sim <target_uid> <emote_id> ---
                        # This is TEXT-ONLY representation (no real emote packets). Admin-only.
                        if inPuTMsG.strip().startswith('/fastburst-sim'):
                            parts = inPuTMsG.strip().split()
                            caller = response.Data.uid
                            if caller not in ADMIN_UIDS:
                                await send_text_message(response.Data.chat_type, "[FF0000]Only admins can use /fastburst-sim.", uid, chat_id, key, iv)
                                continue
                            if len(parts) < 3:
                                await send_text_message(response.Data.chat_type, "[FF0000]Usage: /fastburst-sim <target_uid> <emote_id>", uid, chat_id, key, iv)
                                continue
                            try:
                                target_uid = int(parts[1])
                                emote_id = parts[2]
                                # build a simulated line repeating the emote tag 20 times (text only)
                                rep = " ".join([f"[EMOTE:{emote_id}]" for _ in range(20)])
                                sim_msg = f"[00BFFF]Simulated fast emote x20 to {target_uid}:\n{rep}"
                                await send_text_message(response.Data.chat_type, sim_msg, uid, chat_id, key, iv)
                            except ValueError:
                                await send_text_message(response.Data.chat_type, "[FF0000]Invalid UID.", uid, chat_id, key, iv)
                            continue

                        # Existing handlers from original file (e.g., /5, /x/, @a, /solo, /s, help message, etc.)
                        if inPuTMsG.startswith(("/5")):
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C][000000]❄️Done\n\n"
                                P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                                PAc = await OpEnSq(key , iv,region)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , PAc)
                                C = await cHSq(5, uid ,key, iv,region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , C)
                                V = await SEnd_InV(5 , uid , key , iv,region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , V)
                                E = await ExiT(None , key , iv)
                                await asyncio.sleep(3)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , E)
                            except:
                                print('msg in squad')



                        if inPuTMsG.startswith('/x/'):
                            CodE = inPuTMsG.split('/x/')[1]
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                EM = await GenJoinSquadsPacket(CodE , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)


                            except:
                                print('msg in squad')

                        if inPuTMsG.startswith('/solo'):
                            leave = await ExiT(uid,key,iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , leave)

                        if inPuTMsG.strip().startswith('/s'):
                            EM = await FS(key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)

                        if inPuTMsG.strip().startswith('@a'):

                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C][000000]\n\nOnly In Squad ! \n\n"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                            except:
                                print('msg in squad')

                                parts = inPuTMsG.strip().split()
                                print(response.Data.chat_type, uid, chat_id)
                                message = f'[B][C]{get_random_color()}\nEMOTE STARTED-> {xMsGFixinG(uid)}\n'

                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)

                                uid2 = uid3 = uid4 = uid5 = None
                                s = False

                                try:
                                    uid = int(parts[1])
                                    uid2 = int(parts[2])
                                    uid3 = int(parts[3])
                                    uid4 = int(parts[4])
                                    uid5 = int(parts[5])
                                    idT = int(parts[5])

                                except ValueError as ve:
                                    print("ValueError:", ve)
                                    s = True

                                except Exception:
                                    idT = len(parts) - 1
                                    idT = int(parts[idT])
                                    print(idT)
                                    print(uid)

                                if not s:
                                    try:
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                        H = await Emote_k(uid, idT, key, iv,region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)

                                        if uid2:
                                            H = await Emote_k(uid2, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid3:
                                            H = await Emote_k(uid3, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid4:
                                            H = await Emote_k(uid4, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid5:
                                            H = await Emote_k(uid5, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        

                                    except Exception as e:
                                        pass


                        if inPuTMsG in ("hi" , "/help" , "start" , "help"):
                            uid = response.Data.uid
                            chat_id = response.Data.Chat_ID
                            message = '[FF2400][b][c]✨  TURJO HACKER ✨[c]\n[FFFFFF]━━━━━━━━━━━━━━━━━━━━[c]\n[00FF00]🎮 ⚡EMOTE COMMANDS⚡:[c]t\n[FFFF00]@a [uid] [emote-id][c] - Perform Emote\n[FFFF00]/x/ [team code][c] - Invite BOT \n[FFFF00]/5[c] - 5 Player Squad\n[FFFF00]/solo[c] - Leave Squad\n[FFFFFF]━━━━━━━━━━━━━━━━━━━━[c]\n[00BFFF]🔍 ©️PAID COMMANDS:[c]\n[FFFF00]/info [id][c] - Player Info\n[FFFF00]/like [id][c] - Send Likes\n[FFFF00]/visit [id][c] - Send Visits\n[FFFFFF]━━━━━━━━━━━━━━━━━━━━[c]\n[FF69B4]⚡ Safe & Legit Bot\n\n[FF0000]নিয়ম:- [00FF00]প্রতি সপ্তাহে 1000 গ্লোরি না করলে গিল্ড থেকে কিক দেওয়া হবে\n\n[FF0000]RULES:- [00FF00]In Every Week, If You Not Complete 1000 Glory, I Will Kick You From Guild'
                            P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                        response = None
                            
            whisper_writer.close() ; await whisper_writer.wait_closed() ; whisper_writer = None
                    
                    	
                    	
        except Exception as e: print(f"ErroR {ip}:{port} - {e}") ; whisper_writer = None
        await asyncio.sleep(reconnect_delay)

async def MaiiiinE():
    Uid , Pw = '4279335658','31EDD7EAF5C6A2C73A22569AC52A1C6908D0BE551B91BF373CB0AD3CE6021723'
    

    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: print("ErroR - InvaLid AccounT") ; return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") ; return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp
    
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: print("ErroR - GeTinG PorTs From LoGin DaTa !") ; return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    #print(acc_name)
    print(ToKen)
    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()
    
    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , key , iv , LoGinDaTaUncRypTinG , ready_event ,region))
     
    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , key , iv , AutHToKen))
    os.system('clear')
    print(render('ALAMIN.', colors=['white', 'green'], align='center'))
    print('')
    #print(' - ReGioN => {region}'.format(region))
    print(f" - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")    
    print(f" - Subscribe > YOUTUBE |  ALAMIN! (:")    
    await asyncio.gather(task1 , task2)
    
async def StarTinG():
    while True:
        try: await asyncio.wait_for(MaiiiinE() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: print("Token ExpiRed ! , ResTartinG")
        except Exception as e: print(f"Starting - {e} => Please Wait...")

if __name__ == '__main__':
    asyncio.run(StarTinG())
