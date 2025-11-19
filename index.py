import asyncio, requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, base64, re, socket, threading, ssl, pytz, aiohttp, random
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import *
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2, sQ_pb2, Team_msg_pb2
from cfonts import render

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global Variables
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False

# ----------------- Helpers -----------------
def get_random_color():
    colors = ["[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]",
              "[FFFFFF]", "[FFA500]", "[A52A2A]", "[800080]", "[808080]", "[C0C0C0]",
              "[FFC0CB]", "[FFD700]", "[ADD8E6]", "[90EE90]", "[D2691E]", "[DC143C]",
              "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]", "[7CFC00]",
              "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]",
              "[6495ED]", "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]",
              "[8FBC8F]", "[2E8B57]", "[3CB371]", "[6B8E23]", "[808000]", "[B8860B]",
              "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]", "[9932CC]",
              "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]",
              "[191970]", "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]",
              "[AFEEEE]", "[E0FFFF]", "[F5F5DC]", "[FAEBD7]"]
    return random.choice(colors)

# ----------------- API Helpers -----------------
def new_player_info(uid):
    try:
        url = f"https://ff-info-bd.onrender.com/info?uid={uid}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            return f"""
[B][C][11EAFD]★ PLAYER INFO (BD SERVER) ★

[FFFFFF]Name : {data['name']}
Level : {data['level']}
Region : {data['region']}
Likes : {data['likes']}
Account ID : {data['account_id']}
Booyah Pass : {data['booyah_pass']}
Created At : {data['created_at']}

[C][B][FFB300]Powered by TURJO API
"""
        return "[FF0000]Invalid UID or API Error!"
    except Exception:
        return "[FF0000]API Connection Failed!"

def new_send_likes(uid):
    try:
        url = f"https://ff-like-bd.onrender.com/like?uid={uid}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                return f"""
[B][C][11EAFD]★ LIKE SENT SUCCESSFULLY ★

[FFFFFF]Player : {data['player']}
Likes Before : {data['likes_before']}
Likes After : {data['likes_after']}
Added : {data['likes_added']}

[C][B][FFB300]Powered by TURJO API
"""
            return "[FF0000]Already Claimed or Limit Reached!"
        return "[FF0000]Invalid UID or API Error!"
    except Exception:
        return "[FF0000]API Connection Failed!"

# ----------------- /help Command -----------------
def get_command_list():
    commands = [
        "[11EAFD]/emote [teamcode] [uid1] [uid2] ... [emote_id][FFFFFF] - Perform emote and leave automatically",
        "[00FF00]/info [uid][FFFFFF] - Get player info",
        "[FFFF00]/like [uid][FFFFFF] - Send likes",
        "[FF00FF]/visit [uid][FFFFFF] - Send visits",
        "[00BFFF]/solo[FFFFFF] - Leave squad",
        "[FF4500]/5[FFFFFF] - 5 Player Squad",
    ]
    message = "[B][C][FF69B4]✨ TURJO BOT COMMANDS ✨[c]\n"
    for cmd in commands:
        message += cmd + "\n\n"  # one line gap
    message += "[C][B][FFB300]Safe & Legit Bot"
    return message

# ----------------- /emote Command Handler -----------------
async def handle_emote_command(inPuTMsG, response, key, iv, region):
    parts = inPuTMsG.strip().split()
    if len(parts) < 3:
        message = f"[FF0000][B][C]Usage: /emote [teamcode] [uid1] [uid2] ... [emote_id]"
        P = await SEndMsG(response.Data.chat_type, message, response.Data.uid, response.Data.Chat_ID, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
        return

    try:
        team_code = parts[1]
        emote_id = int(parts[-1])
        uids = [int(x) for x in parts[2:-1]]  # all UIDs between teamcode and emote_id

        # Join the squad automatically
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
        await asyncio.sleep(1)  # wait for join to complete

        # Perform emotes for each UID
        for target_uid in uids:
            emote_packet = await Emote_k(target_uid, emote_id, key, iv, region)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', emote_packet)
            await asyncio.sleep(0.5)  # slight delay between emotes

        # Leave the squad automatically
        leave_packet = await ExiT(None, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)

        # Confirmation message
        message = f"[00FF00][B][C]✅ Emotes performed successfully for UIDs: {', '.join(map(str, uids))}"
        P = await SEndMsG(response.Data.chat_type, message, response.Data.uid, response.Data.Chat_ID, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

    except Exception as e:
        message = f"[FF0000][B][C]Error performing emotes: {str(e)}"
        P = await SEndMsG(response.Data.chat_type, message, response.Data.uid, response.Data.Chat_ID, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

# ----------------- CHAT HANDLER -----------------
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , reconnect_delay=0.5):
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
                print(f' - Bot connected with CLAN: {clan_id}')
                pK = await AuthClan(clan_id, clan_compiled_data, key, iv)
                if whisper_writer: whisper_writer.write(pK); await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break
                if data.hex().startswith("120000"):
                    chatdata = json.loads(await DeCode_PackEt(data.hex()[10:]))
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        inPuTMsG = response.Data.msg.lower()
                    except:
                        response = None
                        inPuTMsG = ""
                    if response:
                        if inPuTMsG in ("hi", "/help", "start", "help"):
                            message = get_command_list()
                            P = await SEndMsG(response.Data.chat_type, message, response.Data.uid, response.Data.Chat_ID, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                        elif inPuTMsG.startswith("/emote"):
                            await handle_emote_command(inPuTMsG, response, key, iv, region)

            whisper_writer.close(); await whisper_writer.wait_closed(); whisper_writer = None
        except Exception as e:
            print(f"ErroR {ip}:{port} - {e}")
            whisper_writer = None
        await asyncio.sleep(reconnect_delay)

# ----------------- MAIN -----------------
async def MaiiiinE():
    # Set your account UID and password here
    Uid, Pw = '4279335658', '31EDD7EAF5C6A2C73A22569AC52A1C6908D0BE551B91BF373CB0AD3CE6021723'

    open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
    if not open_id or not access_token: print("ErroR - Invalid Account"); return None

    PyL = await EncRypTMajoRLoGin(open_id, access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: print("Account => Banned or Not Registered"); return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    region = MajoRLoGinauTh.region
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp

    LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP, OnLineporT = OnLinePorTs.split(":")
    ChaTiP, ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName

    AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
    ready_event = asyncio.Event()

    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region))
    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP, OnLineporT, key, iv, AutHToKen))

    os.system('clear')
    print(render('TURJO.', colors=['white', 'green'], align='center'))
    print(f" - BOT ONLINE | UID: {TarGeT} | BOT NAME: {acc_name}")
    await asyncio.gather(task1, task2)

async def StarTinG():
    while True:
        try: await asyncio.wait_for(MaiiiinE(), timeout=7*60*60)
        except asyncio.TimeoutError: print("Token Expired, Restarting...")
        except Exception as e: print(f"Starting - {e} => Please Wait...")

if __name__ == '__main__':
    asyncio.run(StarTinG())
