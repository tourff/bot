import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, base64, datetime, re, socket, threading, ssl, pytz, aiohttp, asyncio, random, logging
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import *
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2, sQ_pb2, Team_msg_pb2
from cfonts import render, say

# Crypto imports used by encrypted_proto
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

logging.basicConfig(level=logging.INFO)

# EMOTES BY TURJO
# FIXED BY TURJO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Variables
# ------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
# ------------------------------------------#

# Provide default/global configuration from environment if missing
# This avoids NameError when these globals are not provided elsewhere.
server2 = os.environ.get("SERVER2", globals().get("server2", "bd"))
key2 = os.environ.get("KEY2", globals().get("key2", ""))
BYPASS_TOKEN = os.environ.get("BYPASS_TOKEN", globals().get("BYPASS_TOKEN", ""))

# Helper: create simple async stubs for external functions that may be missing
def _ensure_async_stub(name, return_value=b""):
    if name not in globals() or not callable(globals().get(name)):
        async def _stub(*args, **kwargs):
            logging.warning("Stub executed for missing function: %s; args=%s kwargs=%s", name, args, kwargs)
            return return_value
        globals()[name] = _stub

def _ensure_sync_stub(name, return_value=None):
    if name not in globals() or not callable(globals().get(name)):
        def _stub(*args, **kwargs):
            logging.warning("Stub executed for missing function: %s; args=%s kwargs=%s", name, args, kwargs)
            return return_value
        globals()[name] = _stub

# Ensure common external functions used in the bot exist (create non-destructive stubs if they don't)
# Async stubs returning bytes or reasonable defaults
_ensure_async_stub("Emote_k", return_value=b"")
_ensure_async_stub("GenJoinSquadsPacket", return_value=b"")
_ensure_async_stub("xSEndMsg", return_value=b"")
_ensure_async_stub("xSEndMsgsQ", return_value=b"")
_ensure_async_stub("EnC_PacKeT", return_value="")           # expected to return hex string
_ensure_async_stub("DecodE_HeX", return_value="")          # expected to return hex string
_ensure_async_stub("DeCode_PackEt", return_value="{}")     # expected to return JSON string
_ensure_async_stub("GeTSQDaTa", return_value=(0, 0, 0))
_ensure_async_stub("AutH_Chat", return_value=b"")
_ensure_async_stub("AuthClan", return_value=b"")
_ensure_async_stub("OpEnSq", return_value=b"")
_ensure_async_stub("cHSq", return_value=b"")
_ensure_async_stub("SEnd_InV", return_value=b"")
_ensure_async_stub("ExiT", return_value=b"")
_ensure_async_stub("FS", return_value=b"")
_ensure_async_stub("Ua", return_value="Dalvik/2.1.0 (Linux; U; Android 11)")

# Sync stubs
_ensure_sync_stub("equie_emote", return_value=None)
_ensure_sync_stub("fix_num", return_value=lambda x: str(x))  # simple fallback if fix_num not provided

# Note:
# - These stubs are intentionally simple and only log their usage.
# - When you integrate the original modules (xC4, xHeaders, etc.), these stubs will be replaced by the real implementations.
# - For testing locally, set SERVER2, KEY2 and BYPASS_TOKEN environment variables or provide these globals in another module.

####################################

# Centralized help message builder (user requested format with a space after commands)
def build_help_message():
    return (
        "[B][C][7FFFD4] ❀ MADE BY TURJO ❀ \n\n"
        "[B][C][FF00FF] See all commands \n"
        "[B][C][FFFF00] /help\n\n"
        "[B][C][16E2F5] Join squad\n"
        "[B][C][0000FF] /join [teamcode]\n\n"
        "[B][C][FF00FF] Leave squad\n"
        "[B][C][FF0000] /solo\n\n"
        "[B][C][FF00FF] Play emotes \n"
        "[B][C][00FF00] /emote [uid] [emote id]\n\n"       
        "[B][C][FF00FF] 3 Player group invite\n"
        "[B][C][FFA500] /3\n\n"
        "[B][C][FF00FF] 5 Palyer group invite\n"
        "[B][C][FFE6E8] /5\n\n"
        "[B][C][FF00FF] 6 player group invite\n"
        "[B][C][FF00FF] /6\n\n"
        "[B][C][FF00FF] Get 100 likes\n"
        "[B][C][FF0000] /like [uid]\n\n"
        "[B][C][FF00FF] Get player info\n"
        "[B][C][16E2F5] /info [uid]\n\n"
        "[B][C][FF00FF] Send Profile visit \n"
        "[B][C][F98B88] /visit [uid]\n\n"
		"[B][C][7FFFD4] ▄︻デ══━一 \n"
    )

# Clan-info-by-clan-id
def Get_clan_info(clan_id):
    try:
        url = f"https://get-clan-info.vercel.app/get_clan_info?clan_id={clan_id}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            msg = f""" 
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
▶▶▶▶GUILD DETAILS◀◀◀◀
Achievements: {data.get('achievements')}
Balance : {fix_num(data.get('balance', 0))}
Clan Name : {data.get('clan_name')}
Expire Time : {fix_num(data.get('guild_details', {}).get('expire_time', 0))}
Members Online : {fix_num(data.get('guild_details', {}).get('members_online', 0))}
Regional : {data.get('guild_details', {}).get('regional')}
Reward Time : {fix_num(data.get('guild_details', {}).get('reward_time', 0))}
Total Members : {fix_num(data.get('guild_details', {}).get('total_members', 0))}
ID : {fix_num(data.get('id', 0))}
Last Active : {fix_num(data.get('last_active', 0))}
Level : {fix_num(data.get('level', 0))}
Rank : {fix_num(data.get('rank', 0))}
Region : {data.get('region')}
Score : {fix_num(data.get('score', 0))}
Timestamp1 : {fix_num(data.get('timestamp1', 0))}
Timestamp2 : {fix_num(data.get('timestamp2', 0))}
Welcome Message: {data.get('welcome_message')}
XP: {fix_num(data.get('xp', 0))}
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY ALAMINgaming.90
            """
            return msg
        else:
            msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Failed to get info, please try again later!!

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY  TURJO 
            """
            return msg
    except Exception as e:
        logging.exception("Get_clan_info error")
        return f"[FF0000]Error while fetching clan info: {e}"


# GET INFO BY PLAYER ID
def get_player_info(player_id):
    url = f"https://like2.vercel.app/player-info?uid={player_id}&server={server2}&key={key2}"
    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}

    if response.status_code == 200:
        try:
            r = response.json()
            return {
                "Account Booyah Pass": f"{r.get('booyah_pass_level', 'N/A')}",
                "Account Create": f"{r.get('createAt', 'N/A')}",
                "Account Level": f"{r.get('level', 'N/A')}",
                "Account Likes": f"{r.get('likes', 'N/A')}",
                "Name": f"{r.get('nickname', 'N/A')}",
                "UID": f"{r.get('accountId', 'N/A')}",
                "Account Region": f"{r.get('region', 'N/A')}",
            }
        except ValueError as e:
            return {"error": "Invalid JSON response"}
    else:
        return {"error": f"Failed to fetch data: {response.status_code}"}


# CHAT WITH AI
def talk_with_ai(question):
    url = f"https://gemini-api-api-v2.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    try:
        res = requests.get(url, timeout=10)
    except requests.exceptions.RequestException:
        return "An error occurred while connecting to the server."
    if res.status_code == 200:
        data = res.json()
        return data.get("message", {}).get("content", "No content in response.")
    else:
        return "An error occurred while connecting to the server."


# SPAM REQUESTS
def spam_requests(player_id):
    url = f"https://like2.vercel.app/send_requests?uid={player_id}&server={server2}&key={key2}"
    try:
        res = requests.get(url, timeout=20)
        if res.status_code == 200:
            data = res.json()
            return f"API Status: Success [{data.get('success_count', 0)}] Failed [{data.get('failed_count', 0)}]"
        else:
            return f"API Error: Status {res.status_code}"
    except requests.exceptions.RequestException as e:
        logging.exception("spam_requests error")
        return "Failed to connect to spam API."


####################################

# ** NEW INFO FUNCTION using the new API **
def newinfo(uid):
    url = "https://like2.vercel.app/player-info"
    params = {
        "uid": uid,
        "server": server2,
        "key": key2,
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "basicInfo" in data:
                return {"status": "ok", "data": data}
            else:
                return {"status": "error", "message": data.get("error", "Invalid ID or data not found.")}
        else:
            try:
                error_msg = response.json().get("error", f"API returned status {response.status_code}")
                return {"status": "error", "message": error_msg}
            except ValueError:
                return {"status": "error", "message": f"API returned status {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"Network error: {str(e)}"}
    except ValueError:
        return {"status": "error", "message": "Invalid JSON response from API."}


# REPLACED send_likes: wrapper that calls like_worker (make sure like_worker.py is present)
def send_likes(uid):
    """
    Wrapper used by the bot. Keeps the same synchronous interface expected by
    the rest of in4.py (since we call it via run_in_executor).
    Reads optional env vars:
      - GUESTS_FILE
      - SERVER2 (server name)
      - DEFAULT_REQUESTED_LIKES
      - DEFAULT_LIKE_CONCURRENCY
    """
    try:
        import os
        from like_worker import send_likes_sync
    except Exception as e:
        logging.exception("send_likes import error: %s", e)
        return "[FF0000]Internal error: like worker missing."

    server_name = os.environ.get("SERVER2", server2 if 'server2' in globals() else "bd")
    requested_likes = int(os.environ.get("DEFAULT_REQUESTED_LIKES", "100"))
    max_concurrent = int(os.environ.get("DEFAULT_LIKE_CONCURRENCY", "20"))
    guests_file = os.environ.get("GUESTS_FILE", "guests_manager/guests_converted.json")

    # Allow user to specify amount via uid string like "<uid>:<amount>" optionally
    uid_str = str(uid)
    amount = requested_likes
    if ":" in uid_str:
        parts = uid_str.split(":", 1)
        uid = parts[0]
        try:
            amount = int(parts[1])
        except Exception:
            amount = requested_likes

    # Call the synchronous worker (runs async tasks internally)
    try:
        result_message = send_likes_sync(str(uid), server_name=server_name, requested_likes=amount, max_concurrent=max_concurrent, guests_file=guests_file)
        return result_message
    except Exception as e:
        logging.exception("send_likes unexpected error: %s", e)
        return f"[FF0000]An unexpected error occurred: {e}"


####################################
# CHECK ACCOUNT IS BANNED

Hr = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB51",
}


# ---- Random Colors ----
def get_random_color():
    colors = [
        "[FF0000]",
        "[00FF00]",
        "[0000FF]",
        "[FFFF00]",
        "[FF00FF]",
        "[00FFFF]",
        "[FFFFFF]",
        "[FFA500]",
        "[A52A2A]",
        "[800080]",
        "[808080]",
        "[C0C0C0]",
        "[FFC0CB]",
        "[FFD700]",
        "[ADD8E6]",
        "[90EE90]",
        "[D2691E]",
        "[DC143C]",
        "[00CED1]",
        "[9400D3]",
        "[F08080]",
        "[20B2AA]",
        "[FF1493]",
        "[7CFC00]",
        "[B22222]",
        "[FF4500]",
        "[DAA520]",
        "[00BFFF]",
        "[00FF7F]",
        "[4682B4]",
        "[6495ED]",
        "[5F9EA0]",
        "[DDA0DD]",
        "[E6E6FA]",
        "[B0C4DE]",
        "[556B2F]",
        "[8FBC8F]",
        "[2E8B57]",
        "[3CB371]",
        "[6B8E23]",
        "[808000]",
        "[B8860B]",
        "[CD5C5C]",
        "[8B0000]",
        "[FF6347]",
        "[FF8C00]",
        "[BDB76B]",
        "[9932CC]",
        "[8A2BE2]",
        "[4B0082]",
        "[6A5ACD]",
        "[7B68EE]",
        "[4169E1]",
        "[1E90FF]",
        "[191970]",
        "[00008B]",
        "[000080]",
        "[008080]",
        "[008B8B]",
        "[B0E0E6]",
        "[AFEEEE]",
        "[E0FFFF]",
        "[F5F5DC]",
        "[FAEBD7]",
    ]
    return random.choice(colors)


async def encrypted_proto(encoded_hex):
    key = b"Yg&tc%DEuh6%Zc^8"
    iv = b"6oyZDr22E3ychjM%"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload


async def GeNeRaTeAccEss(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200:
                return "Failed to get access token"
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
    return await encrypted_proto(string)


async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
            return None


async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr["Authorization"] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
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
    if uid_length == 9:
        headers = "0000000"
    elif uid_length == 8:
        headers = "00000000"
    elif uid_length == 10:
        headers = "000000"
    elif uid_length == 7:
        headers = "000000000"
    else:
        print("Unexpected length")
        headers = "0000000"
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"


async def cHTypE(H):
    if not H:
        return "Squid"
    elif H == 1:
        return "CLan"
    elif H == 2:
        return "PrivaTe"


async def SEndMsG(H, message, Uid, chat_id, key, iv):
    TypE = await cHTypE(H)
    if TypE == "Squid":
        msg_packet = await xSEndMsgsQ(message, chat_id, key, iv)
    elif TypE == "CLan":
        msg_packet = await xSEndMsg(message, 1, chat_id, chat_id, key, iv)
    elif TypE == "PrivaTe":
        msg_packet = await xSEndMsg(message, 2, Uid, Uid, key, iv)
    else:
        msg_packet = None
    return msg_packet


async def SEndPacKeT(OnLinE, ChaT, TypE, PacKeT):
    if TypE == "ChaT" and ChaT:
        whisper_writer.write(PacKeT)
        await whisper_writer.drain()
    elif TypE == "OnLine" and OnLinE:
        online_writer.write(PacKeT)
        await online_writer.drain()
    else:
        return "UnsoPorTed TypE ! >> ErrrroR (:():)"


async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer, spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, XX, uid, Spy, data2, Chat_Leave
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2:
                    break

                if data2.hex().startswith("0500") and len(data2.hex()) > 1000:
                    try:
                        logging.debug("Raw packet: %s", data2.hex()[10:])
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        logging.debug("Decoded packet: %s", packet)
                        # try to parse packet
                        try:
                            packet_json = json.loads(packet)
                            OwNer_UiD, CHaT_CoDe, SQuAD_CoDe = await GeTSQDaTa(packet_json)
                            JoinCHaT = await AutH_Chat(3, OwNer_UiD, CHaT_CoDe, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, "ChaT", JoinCHaT)

                            message = (
                                f"[B][C][FFD700][b][c]\n"
                                f"[00FF00]🤖  TURJO BOT[c]\n"
                                f"[FFFFFF]🚀 Bot Working Now [c]\n"
                                f"[00BFFF]👤 Welcome to the bot![c]\n"
                                f"[FFFFFF]✨ Type /help to see commands[c]\n"
                            )
                            P = await SEndMsG(0, message, OwNer_UiD, OwNer_UiD, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)
                        except Exception:
                            # fallback simple behavior
                            message = f"[B][C]{get_random_color()}\n- WeLComE To Emote Bot !\n\n- Commands : /emote {xMsGFixinG('player_uid')} {xMsGFixinG('909000001')}\n"
                            P = await SEndMsG(0, message, 0, 0, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)
                    except Exception:
                        # ignore non-critical parse errors
                        pass

            online_writer.close()
            await online_writer.wait_closed()
            online_writer = None

        except Exception as e:
            logging.exception("TcPOnLine error")
            online_writer = None
        await asyncio.sleep(reconnect_delay)


async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region, reconnect_delay=0.5):
    print(region, "TCP CHAT")

    global spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, online_writer, chat_id, XX, uid, Spy, data2, Chat_Leave
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print("\n - TarGeT BoT in CLan ! ")
                print(f" - Clan Uid > {clan_id}")
                print(" - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ")
                pK = await AuthClan(clan_id, clan_compiled_data, key, iv)
                if whisper_writer:
                    whisper_writer.write(pK)
                    await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data:
                    break

                if data.hex().startswith("120000"):
                    msg = await DeCode_PackEt(data.hex()[10:])
                    try:
                        chatdata = json.loads(msg)
                    except Exception:
                        chatdata = {}

                    response = None
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = getattr(response.Data, "msg", "").lower()
                    except Exception:
                        response = None
                        inPuTMsG = ""

                    if response:
                        # handle group invite commands (/3, /5, /6) in one block
                        cmd = inPuTMsG.strip()
                        if cmd in ("/3", "/5", "/6"):
                            try:
                                group_size = int(cmd[1:])
                                logging.info("%s command triggered by uid=%s", cmd, uid)
                                message = f"[B][C][000000]❄️Done\n\n"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)
                                PAc = await OpEnSq(key, iv, region)
                                await SEndPacKeT(whisper_writer, online_writer, "OnLine", PAc)
                                C = await cHSq(group_size, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer, "OnLine", C)
                                V = await SEnd_InV(group_size, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer, "OnLine", V)
                                E = await ExiT(None, key, iv)
                                await asyncio.sleep(3)
                                await SEndPacKeT(whisper_writer, online_writer, "OnLine", E)
                            except Exception:
                                logging.exception("Error handling group invite command")

                        # /join handler (supports "/join code" or "join code")
                        elif re.match(r"^/?join\s+.+", inPuTMsG):
                            m = re.match(r"^/?join\s+(.+)", inPuTMsG)
                            if m:
                                CodE = m.group(1).strip()
                                try:
                                    EM = await GenJoinSquadsPacket(CodE, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, "OnLine", EM)
                                except Exception:
                                    logging.exception("Error handling /join")

                        # /info handler - fetch player info and send formatted message
                        elif re.match(r"^/?info\s+\S+", inPuTMsG) or re.match(r"^info\s+\S+", inPuTMsG):
                            m = re.match(r"^/?info\s+(\S+)", inPuTMsG)
                            if m:
                                target = m.group(1)
                                loop = asyncio.get_running_loop()
                                info = await loop.run_in_executor(None, get_player_info, target)
                                if isinstance(info, dict) and "error" in info:
                                    message = f"[FF0000]Error: {info['error']}"
                                else:
                                    try:
                                        message_lines = []
                                        for k, v in info.items():
                                            message_lines.append(f"[FFFFFF]{k} : [00FF00]{v}")
                                        message = "[B][C][00FF00]Player Info:\n" + "\n".join(message_lines)
                                    except Exception:
                                        message = "[FF0000]Failed to format player info."
                            else:
                                message = "[FF0000]Usage: info [uid]  or  /info [uid]"
                            P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)

                        # /like handler - require a space after command; supports "/like 123" and "like 123"
                        elif re.match(r"^/?like\s+\S+", inPuTMsG) or re.match(r"^like\s+\S+", inPuTMsG):
                            m = re.match(r"^/?like\s+(\S+)", inPuTMsG)
                            if m:
                                target = m.group(1)
                                loop = asyncio.get_running_loop()
                                result = await loop.run_in_executor(None, send_likes, target)
                                message = result if result else "[FF0000]Like command failed."
                            else:
                                message = "[FF0000]Usage: /like [uid]"
                            P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)

                        # /visit handler - alias to spam_requests (friend/visit automation)
                        elif re.match(r"^/?visit\s+\S+", inPuTMsG) or re.match(r"^visit\s+\S+", inPuTMsG):
                            m = re.match(r"^/?visit\s+(\S+)", inPuTMsG)
                            if m:
                                target = m.group(1)
                                loop = asyncio.get_running_loop()
                                result = await loop.run_in_executor(None, spam_requests, target)
                                message = result if result else "[FF0000]Visit command failed."
                            else:
                                message = "[FF0000]Usage: /visit [uid]"
                            P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)

                        # /solo handler
                        elif re.match(r"^/?solo\s*$", inPuTMsG) or re.match(r"^solo\s*$", inPuTMsG):
                            try:
                                leave = await ExiT(uid, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, "OnLine", leave)
                            except Exception:
                                logging.exception("Error handling /solo")

                        # /s short command
                        elif re.match(r"^/?s\s*$", inPuTMsG) or re.match(r"^s\s*$", inPuTMsG):
                            try:
                                EM = await FS(key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, "OnLine", EM)
                            except Exception:
                                logging.exception("Error handling /s")

                        # /emote command (supports "/emote uid1 uid2 ... emote_id" and "emote uid1 uid2 ... emote_id")
                        elif re.match(r"^/?emote\s+.+", inPuTMsG) or re.match(r"^emote\s+.+", inPuTMsG):
                            # split preserving tokens, require at least one uid and an emote id at the end
                            tokens = inPuTMsG.strip().split()
                            # remove leading slash if present in first token
                            if tokens and tokens[0].startswith("/"):
                                tokens[0] = tokens[0][1:]
                            if len(tokens) >= 2:
                                # last token should be emote id (attempt to parse)
                                try:
                                    target_emote = int(tokens[-1])
                                except Exception:
                                    target_emote = None
                                target_uids = []
                                for p in tokens[1:-1]:
                                    try:
                                        target_uids.append(int(p))
                                    except Exception:
                                        pass
                                # If user provided only one uid, tokens[1:-1] may be empty; allow single uid when tokens len == 2
                                if not target_uids and len(tokens) == 2:
                                    # only one uid provided before emote id
                                    try:
                                        target_uids = [int(tokens[1])]
                                    except Exception:
                                        target_uids = []
                                if response.Data.chat_type in [0, 1]:
                                    message = f"[B][C][FFFF00]{get_random_color()}\nEMOTE STARTED-> {xMsGFixinG(uid)}\n"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)
                                    for t_uid in target_uids:
                                        try:
                                            H = await Emote_k(t_uid, target_emote, key, iv, region)
                                            await SEndPacKeT(whisper_writer, online_writer, "OnLine", H)
                                            await asyncio.sleep(0.05)
                                        except Exception:
                                            pass
                                else:
                                    message = "[B][C][FFFF00]\n\nOnly In Squad / Guild ! \n\n"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)
                            else:
                                message = "[FF0000]Usage: /emote [uid1] [uid2] ... [emote_id]"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)

                        # help message - trigger with /help or help or hi or start
                        elif inPuTMsG.strip() in ("hi", "/help", "start", "help"):
                            try:
                                message = build_help_message()
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, "ChaT", P)
                            except Exception:
                                logging.exception("Error sending help message")

                        # reset response for safety
                        response = None

            whisper_writer.close()
            await whisper_writer.wait_closed()
            whisper_writer = None

        except Exception as e:
            logging.exception("TcPChaT main loop error")
            whisper_writer = None
        await asyncio.sleep(reconnect_delay)


async def MaiiiinE():
    Uid, Pw = "4279335658", "31EDD7EAF5C6A2C73A22569AC52A1C6908D0BE551B91BF373CB0AD3CE6021723"

    open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
    if not open_id or not access_token:
        print("ErroR - InvaLid AccounT")
        return None

    PyL = await EncRypTMajoRLoGin(open_id, access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE:
        print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ")
        return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp

    LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
    if not LoGinDaTa:
        print("ErroR - GeTinG PorTs From LoGin DaTa !")
        return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP, OnLineporT = OnLinePorTs.split(":")
    ChaTiP, ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    print(ToKen)
    # ensure equie_emote exists (silent if stub)
    try:
        equie_emote(ToKen, UrL)
    except Exception:
        logging.exception("equie_emote call failed (stub?)")
    AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
    ready_event = asyncio.Event()

    task1 = asyncio.create_task(
        TcPChaT(ChaTiP, ChaTporT, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region)
    )

    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP, OnLineporT, key, iv, AutHToKen))
    os.system("clear")
    print(render("TURJO.", colors=["white", "green"], align="center"))
    print("")
    print(f" - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n")
    print(" - BoT sTaTus > GooD | OnLinE ! (:")
    print(" - Subscribe > YOUTUBE |  FALCON LIVE! (:")
    await asyncio.gather(task1, task2)


async def StarTinG():
    while True:
        try:
            await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError:
            print("Token ExpiRed ! , ResTartinG")
        except Exception as e:
            logging.exception("Starting - exception")

if __name__ == "__main__":
    asyncio.run(StarTinG())
