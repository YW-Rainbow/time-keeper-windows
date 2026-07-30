# time_keeper.pyw — time-keeper-windows
#
# 가족이 함께 쓰는 윈도우 PC에서 각자의 화면 사용 시간을 '보이게' 하는 도구.
# 이 앱은 잠금 화면이 아니다. 감시·차단 없이 남은 시간을 항상 보여주는 것이
# 핵심이므로, 우회를 막는 코드(입력 후킹·워치독·종료 방어 등)는 의도적으로
# 존재하지 않는다. 설계 원칙과 금지 목록: SPEC.md, CLAUDE.md 참고.

import csv
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tkinter as tk
from datetime import date, datetime, timedelta
from tkinter import messagebox

try:
    import customtkinter as ctk
except ImportError:  # 설치 안내를 띄워야 하므로 import 시점에 죽지 않는다
    ctk = None

IS_WINDOWS = os.name == "nt"
APP_ID = "time-keeper-windows"

# ── 상수: 경로, 색, 글꼴 ────────────────────────────────────────────────

def default_data_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, APP_ID)

FONT = "Malgun Gothic" if IS_WINDOWS else "NanumGothic"
WEEKDAYS = ["월", "화", "수", "목", "금", "토", "일"]

C = {  # 다크 테마 팔레트 (slate 계열 + 파랑 액센트)
    "bg":       "#0f172a",
    "card":     "#1e293b",
    "border":   "#334155",
    "text":     "#f1f5f9",
    "sub":      "#94a3b8",
    "accent":   "#3b82f6",
    "accent2":  "#60a5fa",
    "warn_bg":  "#9a3412",  # 10분 이하: 주황
    "warn_tx":  "#ffedd5",
    "over_bg":  "#991b1b",  # 3분 이하·종료: 빨강
    "over_tx":  "#fee2e2",
    "pause_bg": "#334155",
    "danger":   "#ef4444",
}

DEFAULT_PROFILE = {
    "name": "이름 없음",
    "pin_hash": None,                    # 개인 PIN은 잠금이 아니라 '누가 쓰는지'의 확인용
    "limit_weekday": 60,
    "limit_weekend": 120,
    "no_limit": False,                   # 어른용: 한도 없이 기록만
    "max_extensions_per_day": 3,         # '5분만 더' 하루 횟수 (사람별)
    "allow_consecutive_extensions": True # False면 연장 사이에 대기시간이 필요
}

DEFAULT_CONFIG = {
    "parent_pin_hash": None,
    "warn_at_minutes": [10, 5, 1],
    "extension_minutes": 5,
    "extension_cooldown_minutes": 30,    # '연속 금지'일 때 다음 5분까지 기다리는 시간
    "pause_auto_resume_minutes": 30,
    "winddown_sleep_minutes": 5,         # '오늘은 여기까지' 후 자동 절전까지의 시간
    "widget_right": None,                # 위젯 위치 기억(오른쪽 끝 x). None이면 우측 상단 기본값
    "widget_y": None,
    "profiles": [
        dict(DEFAULT_PROFILE, id=f"p{i}", name=f"가족 {i}") for i in range(1, 6)
    ],
}

DEFAULT_USER_STATE = {
    "used_minutes": 0,
    "extra_minutes": 0,        # 연장으로 늘어난 분 (재부팅해도 유지되어야 해서 상태에 저장)
    "extensions_self": 0,
    "extensions_parent": 0,
    "pause_minutes": 0,
    "paused": False,
    "pause_started": None,     # ISO 시각
    "last_self_extension": None,  # ISO 시각 — '연속 금지' 판정용
    "extension_ended": None,   # 주어진 시간이 실제로 다 떨어진 시각 — 재사용 대기의 기준점
}

CSV_HEADER = ["date", "user", "used_minutes", "limit_minutes",
              "extensions_self", "extensions_parent", "pause_minutes"]

# ── 저장: 원자적 JSON 쓰기, PIN 해시 ────────────────────────────────────

def load_json(path, default):
    # 파일이 없거나 깨졌으면 조용히 기본값. 사용 시간은 잃어도 되는 데이터다.
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else json.loads(json.dumps(default))
    except (OSError, ValueError):
        return json.loads(json.dumps(default))


def save_json_atomic(path, data):
    # 임시 파일에 쓰고 rename. 강제 종료와 겹쳐도 파일이 반쪽만 남지 않게.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def hash_pin(pin):
    # 어차피 우회 가능한 앱이지만 PIN을 재사용하는 습관 때문에 평문은 남기지 않는다.
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return f"pbkdf2_sha256$200000${salt}${dk.hex()}"


def verify_pin(pin, stored):
    try:
        algo, iters, salt, want = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), want)
    except (AttributeError, ValueError):
        return False

# ── Store: 설정·상태·기록의 단일 창구 ───────────────────────────────────

class Store:
    def __init__(self, data_dir=None, now=None):
        self.dir = data_dir or default_data_dir()
        self.config_path = os.path.join(self.dir, "config.json")
        self.state_path = os.path.join(self.dir, "state.json")
        self.log_path = os.path.join(self.dir, "log.csv")
        self.load(now or datetime.now())

    def load(self, now):
        self.config = load_json(self.config_path, DEFAULT_CONFIG)
        self._sanitize_config()
        self.state = load_json(self.state_path, {"date": "", "current_user": None, "users": {}})
        self._sanitize_state()
        self.rollover(now)
        # 앱이 꺼져 있는 동안 일시정지 자동 재개 시간이 지났으면 정리해 둔다
        for u in self.state["users"].values():
            if u.get("paused") and self._pause_elapsed(u, now) >= self.config["pause_auto_resume_minutes"]:
                u["paused"], u["pause_started"] = False, None
        # 앱을 켤 때는 항상 '누가 쓸까요?'부터 다시 묻는다. 이전 사용자를 가정하면
        # 다른 가족의 시간이 남의 이름으로 기록될 수 있다. (그날의 카운터는 유지된다)
        self.state["current_user"] = None
        self.save_state()

    # 손으로 고친 파일도 조용히 수습한다(SPEC 3절). 잘못된 값 하나 때문에
    # 앱이 안 뜨거나 타이머가 멈추는 것보다, 기본값으로 되돌리는 편이 낫다.
    def _sanitize_config(self):
        def as_int(v, fallback, lo=0):
            try:
                return max(lo, int(v))
            except (TypeError, ValueError):
                return fallback
        c = self.config
        for key, val in DEFAULT_CONFIG.items():   # 예전 설정 파일에 없는 키는 기본값으로 채움
            c.setdefault(key, json.loads(json.dumps(val)))
        if not isinstance(c["parent_pin_hash"], str):
            c["parent_pin_hash"] = None
        c["extension_minutes"] = as_int(c["extension_minutes"], 5, lo=1)
        c["extension_cooldown_minutes"] = as_int(c["extension_cooldown_minutes"], 30)
        c["pause_auto_resume_minutes"] = as_int(c["pause_auto_resume_minutes"], 30, lo=1)
        c["winddown_sleep_minutes"] = as_int(c["winddown_sleep_minutes"], 5, lo=1)
        for key in ("widget_right", "widget_y"):   # 위젯 위치: 정수 또는 None
            if not isinstance(c[key], int) or isinstance(c[key], bool):
                c[key] = None
        warns = c["warn_at_minutes"] if isinstance(c["warn_at_minutes"], list) else []
        warns = sorted({as_int(w, 0) for w in warns if as_int(w, 0) > 0}, reverse=True)
        c["warn_at_minutes"] = warns or list(DEFAULT_CONFIG["warn_at_minutes"])
        profiles = [p for p in c["profiles"] if isinstance(p, dict)] if isinstance(c["profiles"], list) else []
        if not profiles:
            profiles = json.loads(json.dumps(DEFAULT_CONFIG["profiles"]))
        seen_ids, seen_names = set(), set()
        for n, p in enumerate(profiles, start=1):
            for key, val in DEFAULT_PROFILE.items():
                p.setdefault(key, val)
            if not isinstance(p.get("id"), str) or p["id"] in seen_ids:
                p["id"] = self._fresh_id(seen_ids)
            seen_ids.add(p["id"])
            p["name"] = str(p["name"]).strip() or f"가족 {n}"
            while p["name"] in seen_names:   # 이름이 겹치면 기록이 섞인다(CSV가 이름 기준)
                p["name"] += " 2"
            seen_names.add(p["name"])
            if not isinstance(p["pin_hash"], str):
                p["pin_hash"] = None
            p["limit_weekday"] = as_int(p["limit_weekday"], 60)
            p["limit_weekend"] = as_int(p["limit_weekend"], 120)
            p["max_extensions_per_day"] = as_int(p["max_extensions_per_day"], 3)
            p["no_limit"] = bool(p["no_limit"])
            p["allow_consecutive_extensions"] = bool(p["allow_consecutive_extensions"])
        c["profiles"] = profiles

    @staticmethod
    def _fresh_id(used):
        i = 1
        while f"p{i}" in used:
            i += 1
        return f"p{i}"

    def _sanitize_state(self):
        s = self.state
        if not isinstance(s.get("date"), str):
            s["date"] = ""
        s.setdefault("date", "")
        users = s.get("users") if isinstance(s.get("users"), dict) else {}
        clean = {}
        for pid, u in users.items():
            base = json.loads(json.dumps(DEFAULT_USER_STATE))
            if isinstance(u, dict):
                base.update({k: u[k] for k in base if k in u})
            for key in ("used_minutes", "extra_minutes", "extensions_self",
                        "extensions_parent", "pause_minutes"):
                try:
                    base[key] = max(0, int(base[key]))
                except (TypeError, ValueError):
                    base[key] = 0
            base["paused"] = bool(base["paused"])
            for key in ("pause_started", "last_self_extension", "extension_ended"):
                if not isinstance(base[key], str):
                    base[key] = None
            clean[pid] = base
        s["users"] = clean
        if not isinstance(s.get("current_user"), str):
            s["current_user"] = None

    # -- 조회 ------------------------------------------------------------

    def profile(self, pid):
        return next((p for p in self.config["profiles"] if p["id"] == pid), None)

    def user(self, pid):
        return self.state["users"].setdefault(pid, json.loads(json.dumps(DEFAULT_USER_STATE)))

    def limit_on(self, profile, day):
        return profile["limit_weekend"] if day.weekday() >= 5 else profile["limit_weekday"]

    def remaining(self, pid, now=None):
        """남은 분. 한도 없는 프로필이면 None."""
        p = self.profile(pid)
        if p is None or p["no_limit"]:
            return None
        day = (now or datetime.now()).date()
        return self.limit_on(p, day) + self.user(pid)["extra_minutes"] - self.user(pid)["used_minutes"]

    def _pause_elapsed(self, u, now):
        try:
            elapsed = (now - datetime.fromisoformat(u["pause_started"])).total_seconds() / 60
            return max(0.0, elapsed)  # 시계가 뒤로 보정돼도 표시가 부풀지 않게
        except (TypeError, ValueError):
            return 0

    def pause_resume_left(self, pid, now=None):
        u = self.user(pid)
        if not u["paused"]:
            return 0
        left = self.config["pause_auto_resume_minutes"] - self._pause_elapsed(u, now or datetime.now())
        return max(0, round(left))

    def can_extend_self(self, pid, now=None):
        """('5분만 더' 가능 여부, 사유, 대기 분). 사유: None | 'no_left' | 'cooldown'"""
        now = now or datetime.now()
        p, u = self.profile(pid), self.user(pid)
        if u["extensions_self"] >= p["max_extensions_per_day"]:
            return False, "no_left", 0
        if not p["allow_consecutive_extensions"] and u["last_self_extension"]:
            # '연속 금지'의 기준: 직전에 늘린 시간이 실제로 끝난 뒤(extension_ended)
            # 대기시간이 지나야 다음 5분을 쓸 수 있다. 일시정지로 늦게 끝나면 그만큼 밀린다.
            # 미래 시각은 now로 클램프 — 시계가 뒤로 보정됐을 때 과대 대기를 막는다.
            try:
                last = min(now, datetime.fromisoformat(u["last_self_extension"]))
                ended = last + timedelta(minutes=self.config["extension_minutes"])
                if u["extension_ended"]:
                    ended = min(now, datetime.fromisoformat(u["extension_ended"]))
                ready = ended + timedelta(minutes=self.config["extension_cooldown_minutes"])
                if now < ready:
                    return False, "cooldown", max(1, round((ready - now).total_seconds() / 60))
            except ValueError:
                pass
        return True, None, 0

    # -- 변경 ------------------------------------------------------------

    def rollover(self, now=None):
        """날짜가 바뀌었으면 전날 기록을 CSV로 남기고 카운터를 리셋한다."""
        now = now or datetime.now()
        today = now.date().isoformat()
        if self.state["date"] == today:
            return False
        if self.state["date"]:
            self._flush_day_to_csv(self.state["date"])
        self.state["date"] = today
        self.state["users"] = {}
        self.state["current_user"] = None   # 새 날은 '누가 쓸까요?'부터 다시
        self.save_state()
        return True

    def _flush_day_to_csv(self, day_str):
        try:
            day = date.fromisoformat(day_str)
        except ValueError:
            return
        for pid, u in self.state["users"].items():
            p = self.profile(pid)
            if p is None:
                continue
            if not any([u["used_minutes"], u["pause_minutes"],
                        u["extensions_self"], u["extensions_parent"]]):
                continue
            limit = "" if p["no_limit"] else self.limit_on(p, day)
            self._append_csv([day_str, p["name"], u["used_minutes"], limit,
                              u["extensions_self"], u["extensions_parent"], u["pause_minutes"]])

    def _append_csv(self, row):
        # 엑셀이 log.csv를 열어 잠그고 있으면 쓰기가 실패한다. 그 한 줄 때문에
        # 타이머 전체가 멈추는 것보다 그날 기록을 포기하는 편이 낫다(잃어도 되는 데이터).
        try:
            os.makedirs(self.dir, exist_ok=True)
            is_new = not os.path.exists(self.log_path)
            # 새 파일만 BOM(utf-8-sig): 엑셀이 한글을 바로 읽는다. 이어쓰기는 BOM 없이.
            with open(self.log_path, "a", newline="", encoding="utf-8-sig" if is_new else "utf-8") as f:
                w = csv.writer(f)
                if is_new:
                    w.writerow(CSV_HEADER)
                w.writerow(row)
        except OSError:
            pass

    def flush_user_today(self, pid):
        """프로필 삭제 직전 호출: 오늘 기록을 그 시점까지 CSV로 남기고 상태를 지운다.
        상태를 지워야 나중에 같은 id가 재사용돼도 남의 카운터를 물려받지 않는다."""
        p, u = self.profile(pid), self.user(pid)
        if p and any([u["used_minutes"], u["pause_minutes"],
                      u["extensions_self"], u["extensions_parent"]]):
            try:  # 상태가 대표하는 날짜로 기록한다(실제 시계 날짜가 아니라)
                day = date.fromisoformat(self.state["date"])
            except (TypeError, ValueError):
                day = date.today()
            limit = "" if p["no_limit"] else self.limit_on(p, day)
            self._append_csv([day.isoformat(), p["name"], u["used_minutes"], limit,
                              u["extensions_self"], u["extensions_parent"], u["pause_minutes"]])
        self.state["users"].pop(pid, None)
        self.save_state()

    def tick(self, now=None):
        """60초마다 호출. 발생한 사건 문자열을 돌려준다: None | 'auto_resumed'"""
        now = now or datetime.now()
        self.rollover(now)
        pid = self.state["current_user"]
        event = None
        if pid and self.profile(pid):
            u = self.user(pid)
            if u["paused"]:
                u["pause_minutes"] += 1
                if self._pause_elapsed(u, now) >= self.config["pause_auto_resume_minutes"]:
                    u["paused"], u["pause_started"] = False, None
                    event = "auto_resumed"   # 켜두고 잊는 걸 막는 용도. 기록은 남는다
            else:
                rem = self.remaining(pid, now)   # 이번 1분을 세기 전의 남은 시간
                if rem is None or rem > 0:
                    u["used_minutes"] += 1
                    # 이번 증가로 한도에 도달했으면 그 시각을 남긴다('연속 금지' 재사용 대기의 기준점).
                    if rem is not None and self.remaining(pid, now) <= 0 and u["extension_ended"] is None:
                        u["extension_ended"] = now.isoformat(timespec="seconds")
                # rem<=0이면 세지 않는다. 한도가 끝난 뒤 오버레이 앞에서 시간이 흘러도
                # 남은 시간이 새지 않게 — 2분 기다렸다 '5분만 더'를 눌러도 온전히 5분이 되도록.
        self.save_state()
        return event

    def select_user(self, pid, now=None):
        prev = self.state["current_user"]
        if prev and prev != pid:
            pu = self.user(prev)
            pu["paused"], pu["pause_started"] = False, None  # 떠난 사람의 일시정지는 의미가 없다
        self.state["current_user"] = pid
        self.save_state()

    def set_paused(self, pid, paused, now=None):
        u = self.user(pid)
        u["paused"] = paused
        u["pause_started"] = (now or datetime.now()).isoformat(timespec="seconds") if paused else None
        self.save_state()

    def extend_self(self, pid, now=None):
        now = now or datetime.now()
        u = self.user(pid)
        u["extensions_self"] += 1
        u["extra_minutes"] += self.config["extension_minutes"]
        u["last_self_extension"] = now.isoformat(timespec="seconds")
        u["extension_ended"] = None   # 새 카운트다운 시작
        self.save_state()

    def extend_parent(self, pid, minutes):
        u = self.user(pid)
        u["extensions_parent"] += 1
        u["extra_minutes"] += minutes
        u["extension_ended"] = None   # 새 카운트다운 시작
        self.save_state()

    def save_state(self):
        try:  # 백신 등이 파일을 순간 잠그면 이번 저장만 건너뛴다. 다음 저장에서 복구된다.
            save_json_atomic(self.state_path, self.state)
        except OSError:
            pass

    def save_config(self):
        try:
            save_json_atomic(self.config_path, self.config)
        except OSError:
            pass

    # -- 대시보드용 조회 ---------------------------------------------------

    def read_log(self):
        rows = []
        try:
            with open(self.log_path, newline="", encoding="utf-8-sig") as f:
                for r in csv.DictReader(f):
                    try:
                        rows.append({"date": date.fromisoformat(r["date"]),
                                     "user": r["user"],
                                     "used": int(r["used_minutes"] or 0)})
                    except (KeyError, TypeError, ValueError):
                        continue  # 손으로 편집하다 깨진 줄은 그냥 넘어간다
        except OSError:
            pass
        return rows

    def used_by_date(self, name, log_rows=None):
        """이름 기준 {date: 사용 분}. 오늘 값은 state에서 합친다."""
        rows = self.read_log() if log_rows is None else log_rows
        out = {}
        for r in rows:
            if r["user"] == name:
                out[r["date"]] = out.get(r["date"], 0) + r["used"]
        p = next((p for p in self.config["profiles"] if p["name"] == name), None)
        if p:
            out[date.today()] = out.get(date.today(), 0) + self.user(p["id"])["used_minutes"]
        return out

# ── UI 공통 도우미 ──────────────────────────────────────────────────────

def frameless(win, topmost=True):
    win.overrideredirect(True)
    if topmost:
        win.attributes("-topmost", True)
    if IS_WINDOWS:
        # 모서리 밖을 투명하게 처리해서 둥근 카드처럼 보이게 (윈도우 전용 트릭)
        win.configure(fg_color="#000001")
        win.attributes("-transparentcolor", "#000001")


def make_draggable(win, *handles, on_move=None):
    def press(e):
        win._drag = (e.x_root - win.winfo_x(), e.y_root - win.winfo_y())
    def move(e):
        dx, dy = getattr(win, "_drag", (0, 0))
        win.geometry(f"+{e.x_root - dx}+{e.y_root - dy}")
        if on_move:
            on_move()
    for h in handles:
        h.bind("<Button-1>", press)
        h.bind("<B1-Motion>", move)


def center_window(win, y_ratio=0.38):
    win.update_idletasks()
    x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
    y = int((win.winfo_screenheight() - win.winfo_reqheight()) * y_ratio)
    win.geometry(f"+{max(0, x)}+{max(0, y)}")


def virtual_screen():
    """모든 모니터를 합친 영역 (x, y, w, h)."""
    if IS_WINDOWS:
        gsm = ctypes.windll.user32.GetSystemMetrics
        return gsm(76), gsm(77), gsm(78), gsm(79)
    return 0, 0, None, None


def primary_screen():
    """주 모니터 크기 (w, h). 주 모니터는 항상 (0,0)에서 시작한다."""
    if IS_WINDOWS:
        gsm = ctypes.windll.user32.GetSystemMetrics
        return gsm(0), gsm(1)  # SM_CXSCREEN, SM_CYSCREEN
    return None, None


def sleep_pc():
    # 절전(대기 모드). 되돌릴 수 있는 부드러운 방식이라 최대절전·종료 대신 이걸 쓴다.
    # 시간이 됐다고 앱이 멋대로 부르지 않는다 — 아이가 '오늘은 여기까지'를 고른 뒤에만.
    if IS_WINDOWS:
        try:
            ctypes.windll.powrprof.SetSuspendState(0, 1, 0)  # bHibernate=0 → 절전
        except OSError:
            pass


def shutdown_pc():
    # 정상 종료. 아이가 '지금 컴퓨터 끄기'를 직접 누른 경우에만 부른다(강제 아님).
    if IS_WINDOWS:
        try:
            subprocess.run(["shutdown", "/s", "/t", "0"], creationflags=0x08000000)
        except (OSError, subprocess.SubprocessError):
            pass


def overlay_content_pos(virtual, primary):
    """오버레이 창(가상 화면 전체) 안에서 내용 상자를 놓을 상대 위치 (relx, rely).
    듀얼 모니터에서 두 화면 경계에 버튼이 걸리지 않도록 주 모니터 중앙을 가리킨다.
    상대 좌표라 DPI 배율의 영향을 받지 않는다(창 크기에 대한 비율)."""
    vx, vy, vw, vh = virtual
    pw, ph = primary
    if not (pw and vw):
        return 0.5, 0.5
    return (pw / 2 - vx) / vw, (ph / 2 - vy) / vh


def f(size, bold=False):
    return ctk.CTkFont(family=FONT, size=size, weight="bold" if bold else "normal")


def ask_pin(master, title, subtitle="", verify=None, confirm_new=False):
    """PIN 입력 카드. verify가 있으면 맞을 때까지 부드럽게 재시도, 취소하면 None.
    confirm_new=True면 새 PIN을 두 번 입력받는다."""
    result = {"pin": None}
    dlg = ctk.CTkToplevel(master)
    frameless(dlg)
    card = ctk.CTkFrame(dlg, corner_radius=16, fg_color=C["card"],
                        border_width=1, border_color=C["border"])
    card.pack(padx=2, pady=2)
    ctk.CTkLabel(card, text=title, font=f(16, True), text_color=C["text"]).pack(padx=28, pady=(20, 2))
    sub = ctk.CTkLabel(card, text=subtitle or " ", font=f(12), text_color=C["sub"])
    sub.pack(padx=28)
    entry = ctk.CTkEntry(card, show="●", width=180, justify="center", font=f(18))
    entry.pack(padx=28, pady=10)
    stage = {"first": None}  # confirm_new용: 첫 입력 보관

    def done(_=None):
        pin = entry.get().strip()
        if not pin:
            return
        if confirm_new and stage["first"] is None:
            stage["first"] = pin
            entry.delete(0, "end")
            sub.configure(text="확인을 위해 한 번 더 입력해 주세요.")
            return
        if confirm_new and pin != stage["first"]:
            stage["first"] = None
            entry.delete(0, "end")
            sub.configure(text="두 입력이 서로 달라요. 처음부터 다시 입력해 주세요.")
            return
        if verify and not verify(pin):
            entry.delete(0, "end")
            sub.configure(text="PIN이 맞지 않아요. 다시 한번 입력해 주세요.")
            return
        result["pin"] = pin
        dlg.destroy()

    def cancel():
        dlg.destroy()

    row = ctk.CTkFrame(card, fg_color="transparent")
    row.pack(padx=28, pady=(4, 20))
    ctk.CTkButton(row, text="확인", width=90, font=f(13), command=done).pack(side="left", padx=4)
    ctk.CTkButton(row, text="취소", width=90, font=f(13), fg_color=C["border"],
                  hover_color="#475569", command=cancel).pack(side="left", padx=4)
    entry.bind("<Return>", done)
    center_window(dlg)
    entry.focus_force()
    dlg.grab_set()
    master.wait_window(dlg)
    return result["pin"]

# ── 알림 배너 (윈도우 토스트 대신: 외부 패키지 없이, 어느 창 위에서든 보이게) ──

class Banner:
    def __init__(self, app):
        self.app = app
        self.win = None

    def show(self, text, ms=8000):
        self.close()
        self.win = ctk.CTkToplevel(self.app.root)
        frameless(self.win)
        card = ctk.CTkFrame(self.win, corner_radius=14, fg_color=C["card"],
                            border_width=1, border_color=C["accent"])
        card.pack(padx=2, pady=2)
        ctk.CTkLabel(card, text="⏰  " + text, font=f(14), text_color=C["text"]
                     ).pack(padx=22, pady=14)
        self.win.update_idletasks()
        x = (self.win.winfo_screenwidth() - self.win.winfo_reqwidth()) // 2
        self.win.geometry(f"+{max(0, x)}+24")
        self.win.after(ms, self.close)

    def close(self):
        if self.win is not None and self.win.winfo_exists():
            self.win.destroy()
        self.win = None

# ── 잔여시간 위젯: 항상 보이는 것이 이 앱의 핵심 기능 ─────────────────────

class RemainWidget:
    def __init__(self, app):
        self.app = app
        self.win = ctk.CTkToplevel(app.root)
        frameless(self.win)
        # 닫기·숨기기 기능을 만들지 않는다(CLAUDE.md). 창 장식이 없으니 X 버튼도 없고,
        # Alt+F4로도 닫히지 않게 막는다. 위젯만 닫히고 프로그램은 백그라운드에 남으면
        # '보이지도 않고 새로 켜지지도 않는' 상태가 된다 — 항상 보이는 것이 핵심 기능이라 이걸 막는다.
        self.win.protocol("WM_DELETE_WINDOW", lambda: None)
        self.card = ctk.CTkFrame(self.win, corner_radius=19, fg_color=C["card"],
                                 border_width=1, border_color=C["border"])
        self.card.pack(padx=2, pady=2)
        self.label = ctk.CTkLabel(self.card, text="…", font=f(14, True), text_color=C["text"])
        self.label.pack(padx=18, pady=9)
        make_draggable(self.win, self.card, self.label,   # 게임 UI를 가리면 짜증만 남는다
                       on_move=self._save_anchor)
        for w in (self.card, self.label):
            w.bind("<Button-3>", self.menu)
            w.bind("<Double-Button-1>", lambda e: self.app.show_dashboard())
            w.bind("<ButtonRelease-1>", self._persist)   # 옮긴 자리를 기억한다
        # 문구 길이가 바뀌어도 오른쪽 끝을 기준으로 제자리에 붙어 있게 앵커를 기억한다.
        # 지난번에 옮긴 자리가 있으면 거기서 시작하고, 없으면 우측 상단 기본값.
        cfg = self.app.store.config
        sw, sh = self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        self._right = cfg["widget_right"] if cfg["widget_right"] is not None else sw - 16
        self._y = cfg["widget_y"] if cfg["widget_y"] is not None else 16
        self._right = min(max(60, self._right), sw)      # 화면 밖으로 나가지 않게 살짝 조인다
        self._y = min(max(0, self._y), max(0, sh - 40))
        self.refresh()

    def _save_anchor(self):
        self.win.update_idletasks()
        self._right = self.win.winfo_x() + self.win.winfo_width()
        self._y = self.win.winfo_y()

    def _persist(self, _=None):
        self._save_anchor()
        cfg = self.app.store.config
        cfg["widget_right"], cfg["widget_y"] = self._right, self._y
        self.app.store.save_config()

    def refresh(self):
        s = self.app.store
        pid = s.state["current_user"]
        bg, border, txcolor = C["card"], C["border"], C["text"]
        if pid is None or s.profile(pid) is None:
            text = "사용자를 선택해 주세요"
            txcolor = C["sub"]
        else:
            p, u = s.profile(pid), s.user(pid)
            if u["paused"]:
                text = f"{p['name']} · 일시정지 중 · {s.pause_resume_left(pid)}분 후 다시 시작"
                bg = C["pause_bg"]
            elif p["no_limit"]:
                text = f"{p['name']} · 오늘 {u['used_minutes']}분째 사용 중"
            else:
                rem = s.remaining(pid)
                if rem <= 0:
                    text, bg, txcolor = f"{p['name']} · 오늘 시간이 끝났어요", C["over_bg"], C["over_tx"]
                elif rem <= 3:
                    text, bg, txcolor = f"{p['name']} · {rem}분 남음", C["over_bg"], C["over_tx"]
                elif rem <= 10:
                    text, bg, txcolor = f"{p['name']} · {rem}분 남음", C["warn_bg"], C["warn_tx"]
                else:
                    text = f"{p['name']} · {rem}분 남음"
        self.card.configure(fg_color=bg, border_color=border)
        self.label.configure(text=text, text_color=txcolor)
        self.win.update_idletasks()
        self.win.geometry(f"+{max(0, self._right - self.win.winfo_reqwidth())}+{self._y}")
        self.win.attributes("-topmost", True)  # 다른 topmost 창에 밀리지 않게 주기적으로 갱신

    def menu(self, event):
        s = self.app.store
        pid = s.state["current_user"]
        m = getattr(self, "_menu", None)
        if m is None:   # 상시 실행 앱이라 우클릭마다 새로 만들면 몇 주 새 누적된다
            m = self._menu = tk.Menu(self.win, tearoff=0)
        m.delete(0, "end")
        if pid and s.profile(pid):
            rem = s.remaining(pid)
            if s.user(pid)["paused"]:
                m.add_command(label="다시 시작", command=self.app.resume)
            elif rem is None or rem > 0:   # 시간이 끝난 뒤의 일시정지는 의미가 없다
                m.add_command(label=f"일시정지 ({s.config['pause_auto_resume_minutes']}분 후 자동 재개)",
                              command=self.app.pause)
            m.add_command(label="사용자 바꾸기", command=self.app.switch_user)
        else:
            m.add_command(label="사용자 선택", command=self.app.show_picker)
        m.add_separator()
        m.add_command(label="기록 보기", command=self.app.show_dashboard)
        m.add_command(label="설정 (부모)", command=self.app.show_settings)
        # '종료' 항목은 일부러 없다. 끄고 싶으면 작업 관리자에서 끌 수 있고,
        # 그걸 막지도 숨기지도 않는다. (README '끄는 방법' 참고)
        m.tk_popup(event.x_root, event.y_root)

# ── 사용자 선택 창: PC를 켜면 가장 먼저 만나는 화면 ────────────────────────

class Picker:
    def __init__(self, app):
        self.app = app
        self.win = ctk.CTkToplevel(app.root)
        frameless(self.win)
        self.card = ctk.CTkFrame(self.win, corner_radius=20, fg_color=C["card"],
                                 border_width=1, border_color=C["border"])
        self.card.pack(padx=2, pady=2)
        ctk.CTkLabel(self.card, text="누가 컴퓨터를 쓸까요?", font=f(22, True),
                     text_color=C["text"]).pack(padx=48, pady=(30, 4))
        ctk.CTkLabel(self.card, text="이름을 고르면 남은 시간이 화면에 표시돼요.\n고르지 않으면 시간이 기록되지 않아요.",
                     font=f(13), text_color=C["sub"], justify="center").pack(padx=48, pady=(0, 14))
        s = app.store
        for p in s.config["profiles"]:
            u = s.user(p["id"])
            info = f"오늘 {u['used_minutes']}분 사용" if u["used_minutes"] else "오늘 처음이에요"
            ctk.CTkButton(self.card, text=f"{p['name']}   ·   {info}", font=f(15),
                          height=46, width=320, anchor="w", corner_radius=12,
                          fg_color="#273449", hover_color=C["accent"],
                          command=lambda pid=p["id"]: self.choose(pid)).pack(padx=40, pady=5)
        ctk.CTkButton(self.card, text="나중에 고를게요", font=f(12), width=140, height=30,
                      fg_color="transparent", hover_color=C["border"], text_color=C["sub"],
                      command=self.win.destroy).pack(pady=(12, 22))
        center_window(self.win)
        self.win.attributes("-topmost", True)

    def choose(self, pid):
        p = self.app.store.profile(pid)
        if p is None:   # 이 창이 떠 있는 동안 설정에서 프로필이 지워진 경우
            self.win.destroy()
            self.app.show_picker()
            return
        if p["pin_hash"]:
            ok = ask_pin(self.app.root, f"{p['name']}의 PIN",
                         "본인 확인용이에요. 만들 때 정한 PIN을 입력해 주세요.",
                         verify=lambda s: verify_pin(s, p["pin_hash"]))
            if ok is None:
                return
        self.win.destroy()
        self.app.select_user(pid)

# ── 시간 종료 오버레이 ───────────────────────────────────────────────────

class Overlay:
    """모든 모니터를 덮는 안내 화면. 입력 후킹은 하지 않는다 — 창을 띄우는 것까지만.
    Alt+Tab이나 작업 관리자로 벗어날 수 있어도 괜찮다는 것이 이 앱의 전제다."""

    def __init__(self, app):
        self.app = app
        self.win = ctk.CTkToplevel(app.root)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        x, y, w, h = virtual_screen()
        if not w:  # 윈도우가 아니면 주 화면 크기로 (-fullscreen은 창 관리자에 의존해서 안 쓴다)
            x, y, w, h = 0, 0, self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        # CTk의 geometry()는 크기에 DPI 배율을 한 번 더 곱한다. 이미 물리 픽셀이므로
        # wm_geometry로 우회해야 125%/150% 화면에서도 정확히 전체를 덮는다.
        self.win.wm_geometry(f"{w}x{h}+{x}+{y}")
        self.win.configure(fg_color=C["bg"])
        box = ctk.CTkFrame(self.win, fg_color="transparent")
        # 듀얼 모니터에서 버튼이 두 화면 경계에 걸리지 않게 주 모니터 중앙에 놓는다.
        relx, rely = overlay_content_pos((x, y, w, h), primary_screen())
        box.place(relx=relx, rely=rely, anchor="center")
        self.title = ctk.CTkLabel(box, text="오늘 사용 시간이 끝났어요", font=f(34, True),
                                  text_color=C["text"])
        self.title.pack(pady=(0, 6))
        self.sub = ctk.CTkLabel(box, text="", font=f(16), text_color=C["sub"])
        self.sub.pack(pady=(0, 26))
        self.btn_more = ctk.CTkButton(box, text="5분만 더", font=f(16, True), height=48, width=300,
                                      corner_radius=12, command=self.more)
        self.btn_more.pack(pady=5)
        self.note = ctk.CTkLabel(box, text="", font=f(12), text_color=C["sub"])
        self.note.pack(pady=(0, 8))
        self.pinrow = ctk.CTkFrame(box, fg_color="transparent")  # PIN 확인 후에만 나타나는 줄
        self.btn_pin = ctk.CTkButton(box, text="부모 PIN으로 연장", font=f(14), height=40, width=300,
                                     corner_radius=12, fg_color="#273449", hover_color=C["accent"],
                                     command=self.parent_extend)
        self.btn_pin.pack(pady=5)
        self.btn_switch = ctk.CTkButton(box, text="사용자 바꾸기", font=f(14), height=40, width=300,
                                        corner_radius=12, fg_color="#273449", hover_color=C["accent"],
                                        command=self.app.switch_user)
        self.btn_switch.pack(pady=5)
        self.btn_done = ctk.CTkButton(box, text="오늘은 여기까지", font=f(14), height=40, width=300,
                                      corner_radius=12, fg_color="transparent", border_width=1,
                                      border_color=C["border"], hover_color=C["border"],
                                      command=self.app.start_winddown)
        self.btn_done.pack(pady=5)
        self.refresh()

    def refresh(self):
        s = self.app.store
        pid = s.state["current_user"]
        if not pid or not s.profile(pid):
            return
        p, u = s.profile(pid), s.user(pid)
        self.sub.configure(text=f"{p['name']} · 오늘 {u['used_minutes']}분 사용했어요")
        ok, why, wait = s.can_extend_self(pid)
        left = p["max_extensions_per_day"] - u["extensions_self"]
        if ok:
            self.btn_more.configure(state="normal")
            self.note.configure(text=f"비밀번호 없이 오늘 {left}번 더 쓸 수 있어요. 누른 기록은 남아요.")
        elif why == "cooldown":
            self.btn_more.configure(state="disabled")
            self.note.configure(text=f"다음 '5분만 더'는 {wait}분 뒤에 쓸 수 있어요. (오늘 {left}번 남음)")
        else:
            self.btn_more.configure(state="disabled")
            self.note.configure(text="'5분만 더'는 오늘 다 썼어요. 부모 PIN으로는 연장할 수 있어요.")
        self.win.attributes("-topmost", True)

    def more(self):
        s = self.app.store
        pid = s.state["current_user"]
        ok, _, _ = s.can_extend_self(pid)
        if ok:
            s.extend_self(pid)
            self.app.after_extension()

    def parent_extend(self):
        s = self.app.store
        if not s.config["parent_pin_hash"]:
            self.note.configure(text="부모 PIN이 아직 없어요. 위젯 메뉴 → 설정에서 만들 수 있어요.")
            return
        ok = ask_pin(self.app.root, "부모 PIN", "연장할 시간을 고를 수 있어요.",
                     verify=lambda x: verify_pin(x, s.config["parent_pin_hash"]))
        if ok is None or not self.win.winfo_exists():   # 입력 중 자정이 지나 창이 닫힌 경우
            return
        for w in self.pinrow.winfo_children():
            w.destroy()
        self.pinrow.pack(pady=5)
        for m in (15, 30, 60):
            ctk.CTkButton(self.pinrow, text=f"+{m}분", width=92, height=36, font=f(14),
                          command=lambda m=m: self.grant(m)).pack(side="left", padx=4)

    def grant(self, minutes):
        s = self.app.store
        s.extend_parent(s.state["current_user"], minutes)
        self.app.after_extension()

    def destroy(self):
        if self.win.winfo_exists():
            self.win.destroy()


# ── 마무리 안내 ('오늘은 여기까지' 후) ─────────────────────────────────────

class WindDown:
    """아이가 '오늘은 여기까지'를 직접 고른 뒤의 부드러운 마무리.
    강제 종료가 아니다 — 화면은 열어 두어 저장·정리할 수 있고, '지금 컴퓨터 끄기'로
    스스로 끌 수 있으며, 정해둔 시간(기본 5분) 안에 끄지 않으면 절전으로 넘어간다."""

    def __init__(self, app):
        self.app = app
        self.win = ctk.CTkToplevel(app.root)
        frameless(self.win)
        card = ctk.CTkFrame(self.win, corner_radius=16, fg_color=C["card"],
                            border_width=1, border_color=C["accent"])
        card.pack(padx=2, pady=2)
        self.label = ctk.CTkLabel(card, text="", font=f(14), text_color=C["text"], justify="center")
        self.label.pack(padx=22, pady=(14, 8))
        ctk.CTkButton(card, text="지금 컴퓨터 끄기", font=f(13, True), width=200, height=40,
                      command=self.app.shutdown_now).pack(padx=22, pady=(0, 14))
        make_draggable(self.win, card, self.label)
        self.win.update_idletasks()
        x = (self.win.winfo_screenwidth() - self.win.winfo_reqwidth()) // 2
        self.win.geometry(f"+{max(0, x)}+24")
        self.refresh()

    def refresh(self):
        left = self.app.winddown_left()
        self.label.configure(text="오늘은 여기까지예요. 저장할 게 있으면 지금 정리해 주세요.\n"
                                  f"{left}분 뒤에 컴퓨터가 저절로 절전돼요.")
        self.win.attributes("-topmost", True)

    def destroy(self):
        if self.win.winfo_exists():
            self.win.destroy()

# ── 기록 보기 (대시보드): 오늘 · 이번 주 · 최근 4주 ────────────────────────

class Dashboard:
    def __init__(self, app):
        self.app = app
        self.win = ctk.CTkToplevel(app.root)   # 이 창은 보통 창이라 닫아도 된다
        self.win.title("기록 보기 — time-keeper-windows")
        self.win.geometry("820x700")
        self.win.configure(fg_color=C["bg"])
        self.win.attributes("-topmost", True)
        ctk.CTkLabel(self.win, text="오늘", font=f(17, True), text_color=C["text"]
                     ).pack(anchor="w", padx=24, pady=(18, 4))
        self.today_box = ctk.CTkFrame(self.win, corner_radius=14, fg_color=C["card"])
        self.today_box.pack(fill="x", padx=20)
        row = ctk.CTkFrame(self.win, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(16, 6))
        names = [p["name"] for p in app.store.config["profiles"]]
        self.who = ctk.CTkOptionMenu(row, values=names, width=150, font=f(13),
                                     command=lambda _=None: self.draw_chart())
        self.who.pack(side="left")
        self.range = ctk.CTkSegmentedButton(row, values=["이번 주", "최근 4주"], font=f(13),
                                            command=lambda _=None: self.draw_chart())
        self.range.set("이번 주")
        self.range.pack(side="left", padx=10)
        self.canvas = tk.Canvas(self.win, bg=C["bg"], highlightthickness=0, height=330)
        self.canvas.pack(fill="both", expand=True, padx=20, pady=(4, 10))
        ctk.CTkLabel(self.win, text=f"원본 기록: {app.store.log_path}  (엑셀로 열 수 있어요)",
                     font=f(11), text_color=C["sub"]).pack(anchor="w", padx=24, pady=(0, 12))
        self.refresh()
        self.win.bind("<Configure>", lambda e: self.draw_chart() if e.widget is self.win else None)

    def refresh(self):
        names = [p["name"] for p in self.app.store.config["profiles"]]
        self.who.configure(values=names)   # 개명·추가·삭제를 따라간다
        if self.who.get() not in names:
            self.who.set(names[0])
        for w in self.today_box.winfo_children():
            w.destroy()
        s = self.app.store
        today = date.today()
        for p in s.config["profiles"]:
            u = s.user(p["id"])
            r = ctk.CTkFrame(self.today_box, fg_color="transparent")
            r.pack(fill="x", padx=16, pady=6)
            ctk.CTkLabel(r, text=p["name"], font=f(13, True), width=110, anchor="w",
                         text_color=C["text"]).pack(side="left")
            bar = ctk.CTkProgressBar(r, height=10)
            bar.pack(side="left", fill="x", expand=True, padx=10)
            if p["no_limit"]:
                bar.set(0)
                txt = f"{u['used_minutes']}분 · 한도 없음"
            else:
                limit = s.limit_on(p, today) + u["extra_minutes"]
                ratio = u["used_minutes"] / limit if limit else 1
                bar.set(min(1.0, ratio))
                if ratio >= 1:
                    bar.configure(progress_color=C["danger"])
                txt = f"{u['used_minutes']} / {limit}분"
            ctk.CTkLabel(r, text=txt, font=f(12), width=110, anchor="e",
                         text_color=C["sub"]).pack(side="right")
        self.draw_chart()

    def draw_chart(self):
        s = self.app.store
        name = self.who.get()
        used = s.used_by_date(name)
        today = date.today()
        if self.range.get() == "이번 주":
            monday = today - timedelta(days=today.weekday())
            days = [monday + timedelta(days=i) for i in range(7)]
            series = [(WEEKDAYS[d.weekday()], used.get(d, 0), d == today) for d in days]
        else:
            monday = today - timedelta(days=today.weekday())
            series = []
            for i in range(3, -1, -1):
                start = monday - timedelta(weeks=i)
                total = sum(used.get(start + timedelta(days=j), 0) for j in range(7))
                series.append((f"{start.month}/{start.day}~", total, i == 0))
        self._bars(series)

    def _bars(self, series):
        cv = self.canvas
        cv.delete("all")
        w = max(cv.winfo_width(), 300)
        h = max(cv.winfo_height(), 200)
        pl, pr, pt, pb = 46, 16, 24, 34
        maxv = max([v for _, v, _ in series] + [60])
        n = len(series)
        plot_w, plot_h = w - pl - pr, h - pt - pb
        # 눈금 두 줄이면 충분하다. 차트 라이브러리를 쓰지 않는 이유: SPEC 10절(기록 보기).
        for frac in (0.5, 1.0):
            y = h - pb - plot_h * frac
            cv.create_line(pl, y, w - pr, y, fill=C["border"])
            cv.create_text(pl - 8, y, text=f"{round(maxv * frac)}", anchor="e",
                           fill=C["sub"], font=(FONT, 10))
        cv.create_line(pl, h - pb, w - pr, h - pb, fill=C["sub"])
        bw = min(64, plot_w / n * 0.55)
        for i, (label, v, is_now) in enumerate(series):
            cx = pl + plot_w * (i + 0.5) / n
            bh = 0 if maxv == 0 else plot_h * v / maxv
            color = C["accent2"] if is_now else C["accent"]
            if v:
                cv.create_rectangle(cx - bw / 2, h - pb - bh, cx + bw / 2, h - pb,
                                    fill=color, outline="")
                cv.create_text(cx, h - pb - bh - 10, text=f"{v}", fill=C["text"], font=(FONT, 10))
            cv.create_text(cx, h - pb + 14, text=label, fill=C["sub"], font=(FONT, 11))

# ── 설정 (부모): 프로필·한도·PIN·자동 실행 ─────────────────────────────────

class Settings:
    def __init__(self, app):
        self.app = app
        s = app.store
        if s.config["parent_pin_hash"]:
            ok = ask_pin(app.root, "부모 PIN", "설정을 열려면 부모 PIN이 필요해요.",
                         verify=lambda x: verify_pin(x, s.config["parent_pin_hash"]))
            if ok is None:
                return
        else:
            pin = ask_pin(app.root, "부모 PIN 만들기",
                          "설정을 보호할 부모 PIN을 먼저 만들어 주세요.", confirm_new=True)
            if pin is None:
                return
            s.config["parent_pin_hash"] = hash_pin(pin)
            s.save_config()
        self.build()

    def build(self):
        self.win = ctk.CTkToplevel(self.app.root)
        self.win.title("설정 — time-keeper-windows")
        self.win.geometry("900x560")
        self.win.configure(fg_color=C["bg"])
        self.win.attributes("-topmost", True)
        # X로 닫아도 저장으로 취급한다. 추가·삭제·PIN이 반쯤만 적용된 채 남는 걸 막는다.
        self.win.protocol("WM_DELETE_WINDOW", self.save)
        head = ctk.CTkFrame(self.win, fg_color="transparent")
        head.pack(fill="x", padx=20, pady=(16, 2))
        cols = [("이름", 130), ("평일(분)", 70), ("주말(분)", 70), ("한도 없음", 80),
                ("5분더/일", 70), ("연속 허용", 80), ("개인 PIN", 90), ("", 60)]
        for text, width in cols:
            ctk.CTkLabel(head, text=text, font=f(12, True), width=width,
                         text_color=C["sub"]).pack(side="left", padx=4)
        self.list = ctk.CTkScrollableFrame(self.win, fg_color=C["card"], corner_radius=14)
        self.list.pack(fill="both", expand=True, padx=20, pady=6)
        self.rows = []
        for p in self.app.store.config["profiles"]:
            self.add_row(p)
        foot = ctk.CTkFrame(self.win, fg_color="transparent")
        foot.pack(fill="x", padx=20, pady=(6, 16))
        ctk.CTkButton(foot, text="+ 프로필 추가", font=f(13), width=110,
                      fg_color="#273449", hover_color=C["accent"],
                      command=self.add_profile).pack(side="left")
        ctk.CTkButton(foot, text="부모 PIN 변경", font=f(13), width=110,
                      fg_color="#273449", hover_color=C["accent"],
                      command=self.change_parent_pin).pack(side="left", padx=8)
        self.auto_btn = ctk.CTkButton(foot, text=self.auto_label(), font=f(13), width=170,
                                      fg_color="#273449", hover_color=C["accent"],
                                      command=self.toggle_autostart)
        self.auto_btn.pack(side="left", padx=8)
        ctk.CTkButton(foot, text="저장하고 닫기", font=f(13, True), width=130,
                      command=self.save).pack(side="right")

    def add_row(self, p):
        r = ctk.CTkFrame(self.list, fg_color="transparent")
        r.pack(fill="x", pady=4)
        name = ctk.CTkEntry(r, width=130, font=f(13))
        name.insert(0, p["name"])
        wd = ctk.CTkEntry(r, width=70, font=f(13), justify="center")
        wd.insert(0, str(p["limit_weekday"]))
        we = ctk.CTkEntry(r, width=70, font=f(13), justify="center")
        we.insert(0, str(p["limit_weekend"]))
        nolim = ctk.CTkCheckBox(r, text="", width=80)
        if p["no_limit"]:
            nolim.select()
        ext = ctk.CTkEntry(r, width=70, font=f(13), justify="center")
        ext.insert(0, str(p["max_extensions_per_day"]))
        consec = ctk.CTkCheckBox(r, text="", width=80)
        if p["allow_consecutive_extensions"]:
            consec.select()
        pin_btn = ctk.CTkButton(r, text="변경·삭제" if p["pin_hash"] else "만들기", width=90, font=f(12),
                                fg_color="#273449", hover_color=C["accent"])
        pin_btn.configure(command=lambda p=p, b=pin_btn: self.child_pin(p, b))
        rm = ctk.CTkButton(r, text="삭제", width=60, font=f(12), fg_color="transparent",
                           border_width=1, border_color=C["border"], hover_color=C["over_bg"],
                           command=lambda: self.remove_row(r, p))
        for w_, pad in [(name, 4), (wd, 4), (we, 4), (nolim, 4), (ext, 4), (consec, 4), (pin_btn, 4), (rm, 4)]:
            w_.pack(side="left", padx=pad)
        self.rows.append((p, r, name, wd, we, nolim, ext, consec))

    def add_profile(self):
        s = self.app.store
        pid = Store._fresh_id({p["id"] for p in s.config["profiles"]})
        p = dict(DEFAULT_PROFILE, id=pid, name=f"가족 {pid[1:]}")
        s.config["profiles"].append(p)
        self.add_row(p)

    def remove_row(self, row, p):
        if len([r for r in self.rows if r[1].winfo_exists()]) <= 1:
            return  # 최소 한 명은 남긴다
        row.destroy()
        s = self.app.store
        s.flush_user_today(p["id"])   # 오늘 기록을 남기고 상태를 지운다 (id 재사용 대비)
        s.config["profiles"] = [x for x in s.config["profiles"] if x["id"] != p["id"]]
        if s.state["current_user"] == p["id"]:
            s.state["current_user"] = None

    def child_pin(self, p, btn):
        if p["pin_hash"] and messagebox.askyesno(
                APP_ID, f"{p['name']}의 PIN을 없앨까요?\n('아니요'를 누르면 새 PIN을 만들어요.)",
                parent=self.win):
            p["pin_hash"] = None
            self.app.store.save_config()
            if btn.winfo_exists():
                btn.configure(text="만들기")
            return
        pin = ask_pin(self.app.root, f"{p['name']}의 PIN", "4자리 숫자를 추천해요.",
                      confirm_new=True)
        if pin is not None:
            p["pin_hash"] = hash_pin(pin)
            self.app.store.save_config()
            if btn.winfo_exists():   # PIN 입력 중 설정 창이 닫혔을 수 있다
                btn.configure(text="변경·삭제")

    def change_parent_pin(self):
        s = self.app.store
        pin = ask_pin(self.app.root, "새 부모 PIN", "새로 사용할 부모 PIN을 입력해 주세요.",
                      confirm_new=True)
        if pin is not None:
            s.config["parent_pin_hash"] = hash_pin(pin)
            s.save_config()

    def auto_label(self):
        return "자동 실행: 해제하기" if is_autostart_enabled() else "자동 실행: 등록하기"

    def toggle_autostart(self):
        ok, err = set_autostart(not is_autostart_enabled())
        if not ok:
            messagebox.showinfo(APP_ID, f"자동 실행 설정이 잘 안 됐어요.\n{err}", parent=self.win)
        self.auto_btn.configure(text=self.auto_label())

    def save(self):
        def to_int(entry, fallback):
            try:
                return max(0, int(entry.get().strip()))
            except ValueError:
                return fallback
        for p, row, name, wd, we, nolim, ext, consec in self.rows:
            if not row.winfo_exists():
                continue
            p["name"] = name.get().strip() or p["name"]
            p["limit_weekday"] = to_int(wd, p["limit_weekday"])
            p["limit_weekend"] = to_int(we, p["limit_weekend"])
            p["no_limit"] = bool(nolim.get())
            p["max_extensions_per_day"] = to_int(ext, p["max_extensions_per_day"])
            p["allow_consecutive_extensions"] = bool(consec.get())
        names = [p["name"] for p in self.app.store.config["profiles"]]
        if len(names) != len(set(names)):
            # CSV가 이름 기준이라 이름이 겹치면 두 사람의 기록이 섞인다
            messagebox.showinfo(APP_ID, "이름이 서로 같은 가족이 있어요.\n각자 다른 이름으로 정해 주세요.",
                                parent=self.win)
            return
        self.app.store.save_config()
        self.app.store.save_state()
        self.win.destroy()
        self.app.check_time()   # 한도가 바뀌었으면 오버레이도 즉시 따라간다
        self.app.refresh_all()
        if self.app.picker is not None and self.app.picker.win.winfo_exists():
            self.app.show_picker()   # 열려 있는 선택 창에 개명·추가·삭제를 반영

# ── 자동 실행: shell:startup 바로가기. 몰래 등록하지 않는다 ─────────────────

def startup_lnk_path():
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                        "Start Menu", "Programs", "Startup", f"{APP_ID}.lnk")


def is_autostart_enabled():
    return IS_WINDOWS and os.path.exists(startup_lnk_path())


def set_autostart(enable):
    if not IS_WINDOWS:
        return False, "윈도우에서만 쓸 수 있어요."
    lnk = startup_lnk_path()
    try:
        if not enable:
            if os.path.exists(lnk):
                os.remove(lnk)
            return True, ""
        script = os.path.abspath(__file__)
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        target = pyw if os.path.exists(pyw) else sys.executable
        # 레지스트리 대신 시작프로그램 폴더: 사용자가 눈으로 확인하고 지울 수 있다.
        q = lambda t: t.replace("'", "''")
        ps = (f"$ws = New-Object -ComObject WScript.Shell; "
              f"$s = $ws.CreateShortcut('{q(lnk)}'); "
              f"$s.TargetPath = '{q(target)}'; "
              f"$s.Arguments = '\"{q(script)}\"'; "
              f"$s.WorkingDirectory = '{q(os.path.dirname(script))}'; "
              f"$s.Save()")
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                       check=True, capture_output=True, creationflags=0x08000000)
        return True, ""
    except (OSError, subprocess.CalledProcessError) as e:
        return False, str(e)

# ── 앱 본체: 60초 틱, 창들 사이의 교통정리 ─────────────────────────────────

class App:
    def __init__(self, store):
        self.store = store
        self.root = ctk.CTk()
        self.root.withdraw()   # 뿌리 창은 숨긴다. 보이는 것은 위젯·선택 창뿐
        self.banner = Banner(self)
        self.overlay = None
        self.dashboard = None
        self.picker = None
        self.settings = None
        self.winddown = None
        self.winddown_until = None   # '오늘은 여기까지' 후 절전까지 남은 시각
        self.warned = {}       # {pid: 지나간 경고 시점들} — 같은 시점 중복 알림 금지
        self.widget = RemainWidget(self)
        self.show_picker()     # 시작할 때는 항상 묻는다. 이전 사용자를 가정하지 않는다.
        self.check_time()
        self.root.after(60_000, self.tick)

    # -- 시간 흐름 ---------------------------------------------------------

    def tick(self):
        try:
            rolled = self.store.state["date"] != datetime.now().date().isoformat()
            event = self.store.tick()
            if rolled:
                self.warned.clear()
                self.close_winddown()
                self.close_overlay()
                self.show_picker()
            if event == "auto_resumed":
                self.banner.show(f"일시정지 {self.store.config['pause_auto_resume_minutes']}분이 지나서 다시 시작했어요.")
            self.check_time()
            self.refresh_all()
        finally:
            # 무슨 일이 있어도 다음 틱은 잡아 둔다. 이 예약이 끊기면 앱 전체가 조용히 멈춘다.
            self.root.after(60_000, self.tick)

    def check_time(self):
        s = self.store
        # '오늘은 여기까지' 마무리 중이면 그 흐름을 우선한다.
        if self.winddown_until is not None:
            if datetime.now() >= self.winddown_until:
                self.close_winddown()
                sleep_pc()   # 정해둔 시간이 지나면 절전. 아이가 고른 마무리의 일부다(강제 아님).
            else:
                self.close_overlay()   # 마무리 중에는 화면을 열어 둔다(저장·정리)
                if self.winddown is None or not self.winddown.win.winfo_exists():
                    self.winddown = WindDown(self)   # 닫혔으면 되살린다
                self.winddown.refresh()
            return
        pid = s.state["current_user"]
        if not pid or not s.profile(pid) or s.profile(pid)["no_limit"]:
            self.close_overlay()
            return
        if s.user(pid)["paused"]:
            return
        rem = s.remaining(pid)
        if rem <= 0:
            self.show_overlay()
            return
        self.close_overlay()
        fired = self.warned.setdefault(pid, set())
        due = [m for m in s.config["warn_at_minutes"] if rem <= m and m not in fired]
        if due:
            fired.update(due)   # 한 번에 하나만 알리고, 지나친 시점은 소진 처리
            tip = " 저장할 게 있으면 지금 해두세요." if rem > 5 else ""
            self.banner.show(f"{rem}분 남았어요.{tip}")

    # -- 사용자 동작 --------------------------------------------------------

    def select_user(self, pid):
        self.close_winddown()
        self.store.select_user(pid)
        self.warned.pop(pid, None)
        self.check_time()
        self.refresh_all()

    def switch_user(self):
        self.close_winddown()
        self.store.select_user(None)
        self.close_overlay()
        self.refresh_all()
        self.show_picker()

    # -- '오늘은 여기까지' 마무리 --------------------------------------------

    def start_winddown(self):
        mins = self.store.config["winddown_sleep_minutes"]
        self.winddown_until = datetime.now() + timedelta(minutes=mins)
        self.close_overlay()   # 화면을 열어 준다 — 저장·정리하고 직접 끌 수 있게
        if self.winddown is None or not self.winddown.win.winfo_exists():
            self.winddown = WindDown(self)
        else:
            self.winddown.refresh()

    def winddown_left(self):
        if not self.winddown_until:
            return 0
        secs = (self.winddown_until - datetime.now()).total_seconds()
        return max(0, int((secs + 59) // 60))   # 분 단위 올림

    def shutdown_now(self):
        self.close_winddown()
        shutdown_pc()

    def close_winddown(self):
        self.winddown_until = None
        if self.winddown is not None:
            self.winddown.destroy()
            self.winddown = None

    def pause(self):
        pid = self.store.state["current_user"]
        if pid:
            self.store.set_paused(pid, True)
            self.refresh_all()

    def resume(self):
        pid = self.store.state["current_user"]
        if pid:
            self.store.set_paused(pid, False)
            self.check_time()
            self.refresh_all()

    def after_extension(self):
        pid = self.store.state["current_user"]
        self.warned.pop(pid, None)   # 연장으로 생긴 시간에는 10/5/1분 경고를 다시 알린다
        self.close_overlay()
        self.refresh_all()

    # -- 창 관리 ------------------------------------------------------------

    def show_picker(self):
        if self.root.grab_current() is not None:
            return  # PIN 카드 위를 topmost 창으로 덮으면 화면이 잠긴 것처럼 보인다
        if self.picker is not None and self.picker.win.winfo_exists():
            self.picker.win.destroy()   # lift 대신 재생성: '오늘 N분' 숫자를 새로 채운다
        self.picker = Picker(self)

    def show_overlay(self):
        if self.overlay is not None and self.overlay.win.winfo_exists():
            self.overlay.refresh()
            return
        if self.root.grab_current() is not None:
            return  # PIN 입력 중에는 만들지 않는다. 다음 틱(1분 안)에 다시 시도된다.
        self.overlay = Overlay(self)

    def close_overlay(self):
        if self.overlay is not None:
            self.overlay.destroy()
            self.overlay = None

    def show_dashboard(self):
        if self.dashboard is not None and self.dashboard.win.winfo_exists():
            self.dashboard.refresh()
            self.dashboard.win.lift()
        else:
            self.dashboard = Dashboard(self)

    def show_settings(self):
        w = getattr(self.settings, "win", None)
        if w is not None and w.winfo_exists():
            w.lift()   # 같은 설정을 두 창에서 고치면 마지막 저장이 이겨버린다
            return
        self.settings = Settings(self)

    def refresh_all(self):
        # 무슨 이유로든 위젯이 사라지면 되살린다. 항상 보이는 것이 이 앱의 핵심 기능이라,
        # 위젯이 없는 채로 프로그램만 도는 상태를 두지 않는다.
        if not self.widget.win.winfo_exists():
            self.widget = RemainWidget(self)
        else:
            self.widget.refresh()
        if self.overlay is not None and self.overlay.win.winfo_exists():
            self.overlay.refresh()
        if self.winddown is not None and self.winddown.win.winfo_exists():
            self.winddown.refresh()
        if self.dashboard is not None and self.dashboard.win.winfo_exists():
            self.dashboard.refresh()

# ── 시작 ────────────────────────────────────────────────────────────────

def already_running():
    # 두 개가 돌면 시간이 두 배로 깎인다. 숨기려는 게 아니라 이중 카운트 방지용.
    if not IS_WINDOWS:
        return False
    # windll.GetLastError()는 ctypes 내부 호출이 값을 덮을 수 있어 신뢰할 수 없다
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW(None, False, f"{APP_ID}-single-instance")
    return ctypes.get_last_error() == 183  # ERROR_ALREADY_EXISTS


def main():
    if ctk is None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(APP_ID, "필요한 패키지가 아직 없어요.\n"
                            "명령 프롬프트에서 아래 한 줄을 실행해 주세요.\n\n"
                            "pip install customtkinter")
        return
    if already_running():
        root = tk.Tk()
        root.withdraw()
        # 위젯이 안 보이는데 이 메시지가 뜨면, 이전 실행이 백그라운드에 남은 것이다.
        # 이 앱은 작업표시줄에 안 뜨고 작업관리자의 '자세히' 탭에만 pythonw.exe로 보이므로
        # 어디서 끝내야 하는지 구체적으로 안내한다.
        messagebox.showinfo(APP_ID,
                            "이미 실행되고 있어요. 화면 오른쪽 위의 위젯을 확인해 주세요.\n\n"
                            "위젯이 보이지 않으면 이전 프로그램이 백그라운드에 남아 있을 수 있어요.\n"
                            "작업 관리자(Ctrl+Shift+Esc)의 '자세히' 탭에서 pythonw.exe를 끝낸 뒤\n"
                            "다시 실행해 주세요.")
        return
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = App(Store())
    app.root.mainloop()


if __name__ == "__main__":
    main()
