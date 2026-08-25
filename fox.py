import ctypes
import hashlib
import io
import os
import secrets
import shutil
import subprocess
import sys
import tempfile 
import threading
import tkinter as tk
import zipfile
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError as exc:
    AESGCM = None
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None

try:
    import pystray
except ModuleNotFoundError:
    pystray = None

try:
    from PIL import Image, ImageDraw
except ModuleNotFoundError:
    Image = None
    ImageDraw = None


# ============================================================
# FOX CONFIGURATION
# ============================================================

APP_NAME = "FOX"

MAGIC = b"FOXLOCK1"
HEADER_VERSION = 2

SALT_SIZE = 16
NONCE_SIZE = 12
HINT_LEN = 512

KEY_LEN = 32
PBKDF2_ROUNDS = 600_000

# Entry types stored in header version 2+. Version 1 files predate this
# byte and are always treated as ENTRY_FILE for backward compatibility.
ENTRY_FILE = 0
ENTRY_FOLDER = 1

# Locked folders are stored as a single encrypted archive file next to
# where the original folder used to be, using this suffix.
FOLDER_SUFFIX = ".foxfolder"


# ============================================================
# WINDOWS ADMIN / UAC
# ============================================================

def is_admin():
    try:
        return bool(
            ctypes.windll.shell32.IsUserAnAdmin()
        )
    except Exception:
        return False


def relaunch_as_admin():

    if not sys.platform.startswith("win"):
        raise RuntimeError(
            "FOX currently requires Windows."
        )

    params = subprocess.list2cmdline(
        sys.argv
    )

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1
    )

    if result <= 32:
        raise RuntimeError(
            "Windows UAC was cancelled or failed."
        )


def ensure_admin():

    if is_admin():
        return

    if not sys.platform.startswith("win"):
        return

    try:
        relaunch_as_admin()

    except Exception as exc:

        root = tk.Tk()
        root.withdraw()

        messagebox.showwarning(
            "FOX // ADMIN ACCESS",
            "Administrator privileges are recommended for full access, but FOX can continue in standard mode.\n\n"
            f"{exc}"
        )

        root.destroy()

    else:

        # An elevated copy of FOX is now starting; this process must not
        # continue on or it would leave two instances of FOX running.
        sys.exit(0)


# ============================================================
# CRYPTOGRAPHY
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ROUNDS,
        dklen=KEY_LEN
    )


def require_crypto():

    if AESGCM is None:
        raise RuntimeError(
            "The 'cryptography' package is not installed. "
            "Install it with: py -m pip install cryptography"
        )


def encrypt_payload(
    data: bytes,
    key: bytes,
    nonce: bytes
) -> bytes:

    require_crypto()

    aes = AESGCM(key)

    return aes.encrypt(
        nonce,
        data,
        MAGIC
    )


def decrypt_payload(
    data: bytes,
    key: bytes,
    nonce: bytes
) -> bytes:

    require_crypto()

    aes = AESGCM(key)

    try:

        return aes.decrypt(
            nonce,
            data,
            MAGIC
        )

    except Exception as exc:

        raise ValueError(
            "Wrong password or corrupted file."
        ) from exc


# ============================================================
# PASSWORD HINT
# ============================================================

def pack_hint(hint: str) -> bytes:

    raw = hint.encode(
        "utf-8"
    )

    if len(raw) > HINT_LEN:

        raise ValueError(
            "Password hint is too long."
        )

    return raw.ljust(
        HINT_LEN,
        b"\x00"
    )


def unpack_hint(data: bytes) -> str:

    return data.rstrip(
        b"\x00"
    ).decode(
        "utf-8",
        errors="replace"
    )


# ============================================================
# HEADER PARSING
# ============================================================

# Bytes needed after the version byte(s): salt + nonce + hint.
FIXED_HEADER_SIZE = (
    SALT_SIZE
    + NONCE_SIZE
    + HINT_LEN
)


def build_locked_blob(
    entry_type: int,
    salt: bytes,
    nonce: bytes,
    hint_data: bytes,
    encrypted: bytes
) -> bytes:

    return (
        MAGIC
        + bytes([HEADER_VERSION])
        + bytes([entry_type])
        + salt
        + nonce
        + hint_data
        + encrypted
    )


def parse_locked_file(blob: bytes):
    """Validate and split a FOX blob into (entry_type, salt, nonce, hint_data, encrypted)."""

    if not blob.startswith(MAGIC):

        raise ValueError(
            "This is not a FOX locked file."
        )

    offset = len(MAGIC)

    if len(blob) < offset + 1:

        raise ValueError(
            "File is corrupted or truncated."
        )

    version = blob[offset]

    offset += 1

    if version == 1:

        # Legacy format: no entry-type byte, files only.
        entry_type = ENTRY_FILE

    elif version == 2:

        if len(blob) < offset + 1:

            raise ValueError(
                "File is corrupted or truncated."
            )

        entry_type = blob[offset]

        offset += 1

    else:

        raise ValueError(
            "Unsupported FOX file version."
        )

    if len(blob) < offset + FIXED_HEADER_SIZE:

        raise ValueError(
            "File is corrupted or truncated."
        )

    salt = blob[
        offset:
        offset + SALT_SIZE
    ]

    offset += SALT_SIZE

    nonce = blob[
        offset:
        offset + NONCE_SIZE
    ]

    offset += NONCE_SIZE

    hint_data = blob[
        offset:
        offset + HINT_LEN
    ]

    offset += HINT_LEN

    encrypted = blob[
        offset:
    ]

    return entry_type, salt, nonce, hint_data, encrypted


def read_header_info(path: Path):
    """Returns (entry_type, hint) for a locked file/folder without decrypting it."""

    blob = path.read_bytes()

    entry_type, _salt, _nonce, hint_data, _encrypted = parse_locked_file(
        blob
    )

    return entry_type, unpack_hint(hint_data)


# ============================================================
# FILE OPERATIONS
# ============================================================

def atomic_replace(
    path: Path,
    data: bytes
):

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.fox-",
        dir=str(path.parent)
    )

    temp_path = Path(
        temp_name
    )

    try:

        with os.fdopen(
            fd,
            "wb"
        ) as file:

            file.write(data)
            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temp_path,
            path
        )

    except Exception:

        try:
            temp_path.unlink(
                missing_ok=True
            )
        except Exception:
            pass

        raise


def is_locked(path: Path):

    if path.is_dir():

        # A plain directory is never itself "locked" - a locked folder
        # exists on disk as a single .foxfolder archive file instead.
        return False

    try:

        with path.open("rb") as file:

            return (
                file.read(
                    len(MAGIC)
                ) == MAGIC
            )

    except OSError:

        return False


def encrypt_file(
    path: Path,
    password: str,
    hint: str = ""
):

    original_data = path.read_bytes()

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    key = derive_key(
        password,
        salt
    )

    encrypted = encrypt_payload(
        original_data,
        key,
        nonce
    )

    blob = build_locked_blob(
        ENTRY_FILE,
        salt,
        nonce,
        pack_hint(hint),
        encrypted
    )

    atomic_replace(
        path,
        blob
    )


def zip_folder(folder: Path) -> bytes:

    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
        zipfile.ZIP_DEFLATED
    ) as archive:

        for item in sorted(folder.rglob("*")):

            arcname = item.relative_to(
                folder
            ).as_posix()

            if item.is_dir():

                # Preserve empty subdirectories.
                archive.writestr(
                    arcname + "/",
                    ""
                )

            else:

                archive.write(
                    item,
                    arcname
                )

    return buffer.getvalue()


def unzip_folder(
    data: bytes,
    dest: Path
):

    with zipfile.ZipFile(
        io.BytesIO(data)
    ) as archive:

        dest_root = dest.resolve()

        for name in archive.namelist():

            member_path = (
                dest / name
            ).resolve()

            if member_path != dest_root and dest_root not in member_path.parents:

                raise ValueError(
                    "Archive contains unsafe paths."
                )

        dest.mkdir(
            parents=True
        )

        archive.extractall(
            dest
        )


def encrypt_folder(
    folder: Path,
    password: str,
    hint: str = ""
) -> Path:

    locked_path = folder.with_name(
        folder.name + FOLDER_SUFFIX
    )

    if locked_path.exists():

        raise ValueError(
            f"'{locked_path.name}' already exists next to this folder."
        )

    archive_data = zip_folder(
        folder
    )

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    key = derive_key(
        password,
        salt
    )

    encrypted = encrypt_payload(
        archive_data,
        key,
        nonce
    )

    blob = build_locked_blob(
        ENTRY_FOLDER,
        salt,
        nonce,
        pack_hint(hint),
        encrypted
    )

    atomic_replace(
        locked_path,
        blob
    )

    try:

        shutil.rmtree(folder)

    except OSError as exc:

        raise RuntimeError(
            f"Folder was encrypted to '{locked_path.name}', but the original "
            f"folder could not be fully removed and may still contain "
            f"unprotected files: {exc}"
        ) from exc

    return locked_path


def unlock_path(
    path: Path,
    password: str
) -> Path:
    """Decrypts a locked FOX file or folder in place.

    Returns the resulting path - unchanged for files, or the restored
    folder path (which differs from `path`) for folders.
    """

    blob = path.read_bytes()

    entry_type, salt, nonce, hint_data, encrypted = parse_locked_file(
        blob
    )

    key = derive_key(
        password,
        salt
    )

    if entry_type == ENTRY_FOLDER:

        archive_data = decrypt_payload(
            encrypted,
            key,
            nonce
        )

        original_name = path.name[
            :-len(FOLDER_SUFFIX)
        ] if path.name.endswith(FOLDER_SUFFIX) else path.stem

        dest = path.with_name(
            original_name
        )

        if dest.exists():

            raise ValueError(
                f"Cannot restore folder: '{original_name}' already exists."
            )

        unzip_folder(
            archive_data,
            dest
        )

        try:

            path.unlink()

        except OSError as exc:

            raise RuntimeError(
                f"Folder restored to '{dest.name}', but the locked archive "
                f"file could not be removed: {exc}"
            ) from exc

        return dest

    decrypted = decrypt_payload(
        encrypted,
        key,
        nonce
    )

    atomic_replace(
        path,
        decrypted
    )

    return path


def read_hint(path: Path):

    _entry_type, hint = read_header_info(
        path
    )

    return hint


# ============================================================
# SYSTEM TRAY ICON
# ============================================================

def create_tray_icon():

    image = Image.new(
        "RGBA",
        (64, 64),
        (11, 14, 16, 255)
    )

    draw = ImageDraw.Draw(
        image
    )

    # FOX symbol
    draw.polygon(
        [
            (10, 18),
            (22, 8),
            (32, 18),
            (42, 8),
            (54, 18),
            (48, 48),
            (32, 56),
            (16, 48)
        ],
        outline=(255, 155, 74, 255),
        width=4
    )

    draw.line(
        [
            (10, 18),
            (32, 30),
            (54, 18)
        ],
        fill=(255, 155, 74, 255),
        width=3
    )

    return image


# ============================================================
# FOX APPLICATION
# ============================================================

class FoxApp(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            "FOX // Watchdog Node"
        )

        self.geometry(
            "920x620"
        )

        self.minsize(
            820,
            560
        )

        self.configure(
            bg="#0b0e10"
        )

        icon_path = Path(__file__).with_name("fox.ico")
        if icon_path.exists():
            try:
                self.iconbitmap(str(icon_path))
            except Exception:
                pass

        self.selected_file = tk.StringVar(
            value="No file selected"
        )

        self.hint_status = tk.StringVar(
            value="Hint: none"
        )

        self.status = tk.StringVar(
            value="SYSTEM READY // ADMIN MODE"
        )

        self.tray_icon = None

        self.protocol(
            "WM_DELETE_WINDOW",
            self.minimize_to_tray
        )

        self.build_style()
        self.build_menu()
        self.build_ui()

        self.start_tray()


    # ========================================================
    # STYLE
    # ========================================================

    def build_style(self):

        style = ttk.Style(
            self
        )

        style.theme_use(
            "clam"
        )

        style.configure(
            "Fox.TButton",

            background="#171b1e",

            foreground="#e6e6e6",

            bordercolor="#a85c1d",

            lightcolor="#a85c1d",

            darkcolor="#0b0e10",

            padding=(
                16,
                10
            ),

            font=(
                "Consolas",
                10,
                "bold"
            )
        )

        style.map(
            "Fox.TButton",

            background=[
                (
                    "active",
                    "#24292d"
                )
            ],

            foreground=[
                (
                    "active",
                    "#ffb46b"
                )
            ]
        )

        style.configure(
            "Fox.TEntry",

            fieldbackground="#111518",

            foreground="#f2f2f2",

            insertcolor="#ff9b4a",

            bordercolor="#4b2a14",

            padding=8,

            font=(
                "Consolas",
                10
            )
        )


    # ========================================================
    # MENU
    # ========================================================

    def build_menu(self):

        menu = tk.Menu(

            self,

            bg="#111518",

            fg="#d6d6d6",

            activebackground="#5f3518",

            activeforeground="#ffffff",

            tearoff=False,

            font=(
                "Consolas",
                10
            )
        )

        lock_menu = tk.Menu(

            menu,

            bg="#111518",

            fg="#d6d6d6",

            activebackground="#5f3518",

            activeforeground="#ffffff",

            tearoff=False
        )

        lock_menu.add_command(
            label="Lock file",
            command=self.lock_file
        )

        lock_menu.add_command(
            label="Unlock file",
            command=self.unlock_file
        )

        lock_menu.add_separator()

        lock_menu.add_command(
            label="Change password",
            command=self.change_password
        )

        lock_menu.add_command(
            label="Delete password / Unlock",
            command=self.delete_password
        )

        menu.add_cascade(
            label="LOCK",
            menu=lock_menu
        )

        menu.add_command(
            label="Select file",
            command=self.select_file
        )

        menu.add_command(
            label="Select folder",
            command=self.select_folder
        )

        menu.add_command(
            label="Minimize to tray",
            command=self.minimize_to_tray
        )

        menu.add_command(
            label="Exit FOX",
            command=self.exit_application
        )

        help_menu = tk.Menu(

            menu,

            bg="#111518",

            fg="#d6d6d6",

            activebackground="#5f3518",

            activeforeground="#ffffff",

            tearoff=False
        )

        help_menu.add_command(
            label="About FOX",
            command=self.about
        )

        menu.add_cascade(
            label="HELP",
            menu=help_menu
        )

        self.config(
            menu=menu
        )


    # ========================================================
    # GUI
    # ========================================================

    def build_ui(self):

        top = tk.Frame(
            self,
            bg="#0b0e10"
        )

        top.pack(
            fill="x",
            padx=28,
            pady=22
        )

        tk.Label(

            top,

            text="FOX",

            bg="#0b0e10",

            fg="#ff9b4a",

            font=(
                "Consolas",
                32,
                "bold"
            )

        ).pack(
            anchor="w"
        )

        tk.Label(

            top,

            text=(
                "WATCHDOG NODE  //  "
                "FILE SECURITY CONSOLE"
            ),

            bg="#0b0e10",

            fg="#737b80",

            font=(
                "Consolas",
                10
            )

        ).pack(
            anchor="w"
        )

        tk.Frame(

            self,

            bg="#5d351b",

            height=1

        ).pack(
            fill="x",
            padx=28
        )

        panel = tk.Frame(

            self,

            bg="#101417",

            highlightbackground="#272d31",

            highlightthickness=1
        )

        panel.pack(

            fill="both",

            expand=True,

            padx=28,

            pady=22
        )

        tk.Label(

            panel,

            text="TARGET FILE",

            bg="#101417",

            fg="#ff9b4a",

            font=(
                "Consolas",
                10,
                "bold"
            )

        ).pack(

            anchor="w",

            padx=24,

            pady=(
                24,
                6
            )
        )

        row = tk.Frame(

            panel,

            bg="#101417"
        )

        row.pack(

            fill="x",

            padx=24
        )

        entry = ttk.Entry(

            row,

            textvariable=self.selected_file,

            state="readonly",

            style="Fox.TEntry"
        )

        entry.pack(

            side="left",

            fill="x",

            expand=True,

            ipady=5
        )

        ttk.Button(

            row,

            text="SELECT FILE",

            style="Fox.TButton",

            command=self.select_file

        ).pack(

            side="left",

            padx=10
        )

        ttk.Button(

            row,

            text="SELECT FOLDER",

            style="Fox.TButton",

            command=self.select_folder

        ).pack(

            side="left"
        )

        tk.Label(

            panel,

            textvariable=self.hint_status,

            bg="#101417",

            fg="#737b80",

            font=(
                "Consolas",
                9
            )

        ).pack(

            anchor="w",

            padx=24,

            pady=(
                7,
                0
            )
        )

        actions = tk.Frame(

            panel,

            bg="#101417"
        )

        actions.pack(

            fill="x",

            padx=24,

            pady=28
        )

        buttons = [

            (
                "LOCK FILE",
                self.lock_file
            ),

            (
                "UNLOCK FILE",
                self.unlock_file
            ),

            (
                "CHANGE PASSWORD",
                self.change_password
            ),

            (
                "DELETE PASSWORD",
                self.delete_password
            )
        ]

        for text, command in buttons:

            ttk.Button(

                actions,

                text=text,

                style="Fox.TButton",

                command=command

            ).pack(

                side="left",

                padx=(
                    0,
                    10
                )
            )

        tk.Label(

            panel,

            text=(

                "FOX encrypts the selected file in place, or locks a whole "
                "folder into a single protected archive.\n\n"

                "Passwords may contain letters, numbers and symbols.\n"

                "Password hints are optional and are displayed before "
                "password entry.\n\n"

                "Closing the window minimizes FOX to the Windows "
                "system tray instead of terminating the application.\n\n"

                "Use the tray menu's EXIT FOX command to terminate FOX."

            ),

            justify="left",

            bg="#101417",

            fg="#8f989d",

            font=(
                "Consolas",
                10
            ),

            wraplength=780

        ).pack(

            anchor="w",

            padx=24,

            pady=4
        )

        status_bar = tk.Frame(

            self,

            bg="#111518"
        )

        status_bar.pack(

            fill="x",

            side="bottom"
        )

        tk.Label(

            status_bar,

            textvariable=self.status,

            bg="#111518",

            fg="#ff9b4a",

            font=(
                "Consolas",
                9
            ),

            anchor="w"

        ).pack(

            fill="x",

            padx=14,

            pady=7
        )


    # ========================================================
    # SYSTEM TRAY
    # ========================================================

    def start_tray(self):

        if pystray is None or Image is None:
            return

        image = create_tray_icon()
        icon_path = Path(__file__).with_name("fox.ico")
        if icon_path.exists():
            try:
                image = Image.open(icon_path)
            except Exception:
                pass

        menu = pystray.Menu(

            pystray.MenuItem(
                "Open FOX",
                self.tray_open
            ),

            pystray.MenuItem(
                "Lock selected file",
                self.tray_lock
            ),

            pystray.MenuItem(
                "Unlock selected file",
                self.tray_unlock
            ),

            pystray.Menu.SEPARATOR,

            pystray.MenuItem(
                "Exit FOX",
                self.tray_exit
            )
        )

        self.tray_icon = pystray.Icon(

            "FOX",

            image,

            "FOX // Watchdog Node",

            menu
        )

        threading.Thread(

            target=self.tray_icon.run,

            daemon=True

        ).start()


    def minimize_to_tray(self):

        if self.tray_icon is None:

            # No tray icon is running, so hiding the window would make
            # FOX unreachable. Exit instead of vanishing silently.
            self.exit_application()
            return

        self.withdraw()

        self.set_status(
            "BACKGROUND MODE // FOX RUNNING IN SYSTEM TRAY"
        )


    def tray_open(
        self,
        icon=None,
        item=None
    ):

        self.after(
            0,
            self.restore_window
        )


    def restore_window(self):

        self.deiconify()

        self.lift()

        self.attributes(
            "-topmost",
            True
        )

        self.after(
            100,
            lambda: self.attributes(
                "-topmost",
                False
            )
        )

        self.set_status(
            "SYSTEM READY // ADMIN MODE"
        )


    def tray_lock(
        self,
        icon=None,
        item=None
    ):

        self.after(
            0,
            self.lock_file
        )


    def tray_unlock(
        self,
        icon=None,
        item=None
    ):

        self.after(
            0,
            self.unlock_file
        )


    def tray_exit(
        self,
        icon=None,
        item=None
    ):

        self.after(
            0,
            self.exit_application
        )


    def exit_application(self):

        if self.tray_icon:

            try:
                self.tray_icon.stop()
            except Exception:
                pass

        try:
            self.destroy()
        except Exception:
            pass

        # Guarantee the process actually terminates instead of lingering
        # in Task Manager (e.g. a stuck tray backend thread).
        os._exit(0)


    # ========================================================
    # FILE SELECTION
    # ========================================================

    def select_file(self):

        path = filedialog.askopenfilename(

            title="Select target file",

            filetypes=[
                (
                    "All files",
                    "*"
                ),
                (
                    "Text files",
                    "*.txt"
                )
            ]
        )

        if not path:
            return

        target = Path(
            path
        )

        self.selected_file.set(
            str(target)
        )

        if is_locked(target):

            entry_type = ENTRY_FILE

            try:

                entry_type, hint = read_header_info(
                    target
                )

                self.hint_status.set(

                    f"Hint: "
                    f"{hint if hint else 'none'}"
                )

            except Exception:

                self.hint_status.set(
                    "Hint: unavailable"
                )

            if entry_type == ENTRY_FOLDER:

                self.set_status(
                    "TARGET SELECTED // LOCKED FOLDER"
                )

            else:

                self.set_status(
                    "TARGET SELECTED // LOCKED FILE"
                )

        else:

            self.hint_status.set(
                "Hint: none"
            )

            self.set_status(
                "TARGET SELECTED // UNLOCKED"
            )


    def select_folder(self):

        path = filedialog.askdirectory(
            title="Select target folder"
        )

        if not path:
            return

        target = Path(
            path
        )

        self.selected_file.set(
            str(target)
        )

        self.hint_status.set(
            "Hint: none"
        )

        self.set_status(
            "TARGET SELECTED // FOLDER (UNLOCKED)"
        )


    def get_path(self):

        value = self.selected_file.get()

        if value == "No file selected":

            messagebox.showwarning(

                "FOX // TARGET",

                "Select a file first."
            )

            return None

        path = Path(
            value
        )

        if not path.exists():

            messagebox.showerror(

                "FOX // TARGET",

                "The selected file no longer exists."
            )

            return None

        return path


    # ========================================================
    # PASSWORD DIALOGS
    # ========================================================

    def ask_new_password(self):

        password = simpledialog.askstring(

            "FOX // NEW PASSWORD",

            "Enter a password:",

            show="*",

            parent=self
        )

        if password is None:
            return None

        if not password:

            messagebox.showerror(

                "FOX // PASSWORD",

                "Password cannot be empty."
            )

            return None

        confirm = simpledialog.askstring(

            "FOX // CONFIRM PASSWORD",

            "Enter the password again:",

            show="*",

            parent=self
        )

        if confirm != password:

            messagebox.showerror(

                "FOX // PASSWORD",

                "Passwords do not match."
            )

            return None

        return password


    def ask_password(
        self,
        title="FOX // PASSWORD"
    ):

        return simpledialog.askstring(

            title,

            "Enter the file password:",

            show="*",

            parent=self
        )


    def ask_password_hint(self):

        answer = messagebox.askyesno(

            "FOX // PASSWORD HINT",

            "Would you like to add an optional password hint?\n\n"

            "The hint will be visible before the password is entered.\n\n"

            "Do NOT put the actual password inside the hint."
        )

        if not answer:

            return ""


        hint = simpledialog.askstring(

            "FOX // PASSWORD HINT",

            "Enter a password hint:",

            parent=self
        )

        if hint is None:

            return ""


        if len(
            hint.encode("utf-8")
        ) > HINT_LEN:

            messagebox.showerror(

                "FOX // PASSWORD HINT",

                "Hint is too long.\n"
                "Maximum size: 512 bytes."
            )

            return None

        return hint.strip()


    # ========================================================
    # LOCK
    # ========================================================

    def lock_file(self):

        path = self.get_path()

        if not path:
            return

        is_folder = path.is_dir()

        if not is_folder and is_locked(path):

            messagebox.showinfo(

                "FOX // LOCK",

                "This file is already locked."
            )

            return


        password = self.ask_new_password()

        if password is None:
            return


        hint = self.ask_password_hint()

        if hint is None:
            return


        try:

            self.set_status(

                "ENCRYPTING FOLDER // PLEASE WAIT"
                if is_folder else
                "ENCRYPTING // PLEASE WAIT"
            )

            self.update_idletasks()

            if is_folder:

                result_path = encrypt_folder(
                    path,
                    password,
                    hint
                )

            else:

                encrypt_file(
                    path,
                    password,
                    hint
                )

                result_path = path

            self.selected_file.set(
                str(result_path)
            )

            self.hint_status.set(

                f"Hint: "
                f"{hint if hint else 'none'}"
            )

            self.set_status(
                "LOCKED // PASSWORD REQUIRED"
            )

            messagebox.showinfo(

                "FOX // LOCK",

                f"{'Folder' if is_folder else 'File'} locked successfully:\n\n{result_path}"
            )

        except Exception as exc:

            self.set_status(
                "ERROR // LOCK FAILED"
            )

            messagebox.showerror(

                "FOX // ERROR",

                str(exc)
            )


    # ========================================================
    # UNLOCK
    # ========================================================

    def unlock_file(self):

        path = self.get_path()

        if not path:
            return

        if not is_locked(path):

            messagebox.showinfo(

                "FOX // UNLOCK",

                "This file is not locked by FOX."
            )

            return


        try:

            hint = read_hint(
                path
            )

        except Exception:

            hint = ""


        if hint:

            messagebox.showinfo(

                "FOX // PASSWORD HINT",

                f"Password hint:\n\n{hint}"
            )


        password = self.ask_password(

            "FOX // UNLOCK"
        )

        if password is None:
            return


        if not password:

            messagebox.showerror(

                "FOX // PASSWORD",

                "Password cannot be empty."
            )

            return


        try:

            self.set_status(

                "VERIFYING PASSWORD // DECRYPTING"
            )

            self.update_idletasks()

            restored_path = unlock_path(
                path,
                password
            )

            self.selected_file.set(
                str(restored_path)
            )

            self.hint_status.set(
                "Hint: none"
            )

            self.set_status(
                "UNLOCKED // RESTORED"
            )

            messagebox.showinfo(

                "FOX // UNLOCK",

                f"Unlocked successfully:\n\n{restored_path}"
            )

        except ValueError as exc:

            self.set_status(

                "ACCESS DENIED // WRONG PASSWORD"
            )

            messagebox.showerror(

                "FOX // ACCESS DENIED",

                str(exc)
            )

        except Exception as exc:

            self.set_status(
                "ERROR // UNLOCK FAILED"
            )

            messagebox.showerror(

                "FOX // ERROR",

                str(exc)
            )


    # ========================================================
    # CHANGE PASSWORD
    # ========================================================

    def change_password(self):

        path = self.get_path()

        if not path:
            return

        if not is_locked(path):

            messagebox.showinfo(

                "FOX // PASSWORD",

                "Lock the file first."
            )

            return


        old_password = self.ask_password(

            "FOX // CURRENT PASSWORD"
        )

        if old_password is None:
            return


        new_password = self.ask_new_password()

        if new_password is None:
            return


        try:

            blob = path.read_bytes()

            entry_type, salt, nonce, hint_data, encrypted = parse_locked_file(
                blob
            )

            old_hint = unpack_hint(
                hint_data
            )

            old_key = derive_key(
                old_password,
                salt
            )

            plain = decrypt_payload(

                encrypted,

                old_key,

                nonce
            )


            change_hint = messagebox.askyesno(

                "FOX // PASSWORD HINT",

                "Change the existing password hint too?"
            )


            if change_hint:

                new_hint = self.ask_password_hint()

                if new_hint is None:
                    return

            else:

                new_hint = old_hint


            new_salt = secrets.token_bytes(
                SALT_SIZE
            )

            new_nonce = secrets.token_bytes(
                NONCE_SIZE
            )

            new_key = derive_key(

                new_password,

                new_salt
            )

            new_encrypted = encrypt_payload(

                plain,

                new_key,

                new_nonce
            )


            new_blob = build_locked_blob(
                entry_type,
                new_salt,
                new_nonce,
                pack_hint(
                    new_hint
                ),
                new_encrypted
            )


            atomic_replace(
                path,
                new_blob
            )


            self.hint_status.set(

                f"Hint: "
                f"{new_hint if new_hint else 'none'}"
            )

            self.set_status(

                "PASSWORD CHANGED // "
                "FILE REMAINS LOCKED"
            )


            messagebox.showinfo(

                "FOX // PASSWORD",

                "Password changed successfully."
            )


        except Exception:

            self.set_status(

                "PASSWORD CHANGE FAILED"
            )

            messagebox.showerror(

                "FOX // ERROR",

                "Current password is incorrect "
                "or the file is corrupted."
            )


    # ========================================================
    # DELETE PASSWORD
    # ========================================================

    def delete_password(self):

        path = self.get_path()

        if not path:
            return

        if not is_locked(path):

            messagebox.showinfo(

                "FOX // PASSWORD",

                "File is already unlocked."
            )

            return


        confirm = messagebox.askyesno(

            "FOX // DELETE PASSWORD",

            "This will completely decrypt the file or folder.\n\n"

            "The password and password hint will be removed.\n\n"

            "Continue?"
        )

        if not confirm:
            return


        password = self.ask_password(

            "FOX // REMOVE PASSWORD"
        )

        if password is None:
            return


        try:

            restored_path = unlock_path(

                path,

                password
            )

            self.selected_file.set(
                str(restored_path)
            )

            self.hint_status.set(
                "Hint: none"
            )

            self.set_status(

                "PASSWORD REMOVED // "
                "UNLOCKED"
            )

            messagebox.showinfo(

                "FOX // PASSWORD",

                "Password protection removed."
            )

        except ValueError as exc:

            self.set_status(

                "ACCESS DENIED // "
                "PASSWORD NOT REMOVED"
            )

            messagebox.showerror(

                "FOX // ACCESS DENIED",

                str(exc)
            )

        except Exception as exc:

            self.set_status(
                "ERROR // PASSWORD NOT REMOVED"
            )

            messagebox.showerror(

                "FOX // ERROR",

                str(exc)
            )


    # ========================================================
    # ABOUT
    # ========================================================

    def about(self):

        messagebox.showinfo(

            "FOX // ABOUT",

            "FOX\n\n"

            "WATCHDOG NODE // FILE SECURITY CONSOLE\n\n"

            "Features:\n"

            "• AES-256-GCM encryption\n"
            "• PBKDF2 password derivation\n"
            "• Locks both individual files and entire folders\n"
            "• Optional password hints\n"
            "• Windows Administrator/UAC\n"
            "• System Tray background mode\n\n"

            "Locked files and folders stay locked using only their own "
            "contents - no background process is required, so they "
            "remain protected even while FOX is completely closed.\n\n"

            "Closing the window does not terminate FOX.\n"

            "Use the System Tray menu to exit FOX."
        )


# ============================================================
# MAIN
# ============================================================

def main():

    if not sys.platform.startswith("win"):

        root = tk.Tk()

        root.withdraw()

        messagebox.showerror(

            "FOX",

            "FOX is currently designed for Windows."
        )

        root.destroy()

        return


    ensure_admin()


    app = FoxApp()

    app.mainloop()


if __name__ == "__main__":

    main()
