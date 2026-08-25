# FOX // Watchdog Node

A small Windows desktop app for password-protecting individual files or entire
folders in place, using AES-256-GCM. Locked items stay locked using only their
own contents on disk — no background service is required, so protection holds
even while FOX itself is completely closed.

## Features

- AES-256-GCM authenticated encryption with a PBKDF2-HMAC-SHA256 derived key
  (600,000 rounds)
- Locks either a single file or a whole folder (folders are archived into one
  encrypted `.foxfolder` file, then the original folder is removed)
- Optional password hints, shown before the password prompt
- Change password / remove protection without needing to separately
  lock+unlock
- Runs with Administrator privileges when available (UAC prompt on launch)
- Minimizes to the Windows system tray instead of closing; "Exit FOX" fully
  terminates the process

## Requirements

- Windows
- Python 3.9+
- Dependencies in `requirements.txt`:
  ```
  py -m pip install -r requirements.txt
  ```
  - `cryptography` is required for locking/unlocking anything.
  - `pystray` and `Pillow` are optional — without them FOX still runs and
    can lock/unlock files and folders, it just won't have a system tray icon
    (closing the window then exits the app instead of hiding it).

## Running

```
py fox.py
```

FOX will ask for Administrator rights via UAC on launch. If you decline or it
fails, FOX continues in standard mode with reduced access to some files.

## Usage

1. **Select file** or **Select folder** to choose a target.
2. **Lock file** — encrypts the file in place, or folder — zips and encrypts
   the folder into `<FolderName>.foxfolder`, then deletes the original
   folder. You'll be asked for a password and, optionally, a hint.
3. **Unlock file** — decrypts a locked file back to its original contents, or
   restores a locked folder archive back into a real folder with its
   original name and structure.
4. **Change password** — re-encrypts with a new password without fully
   decrypting to disk first.
5. **Delete password** — same as unlock, but framed as permanently removing
   protection.

A locked item can be identified because it either starts with the `FOXLOCK1`
magic bytes (files) or carries the `.foxfolder` extension (folders).

## Building a standalone .exe

A PyInstaller spec (`fox.spec`) is included:

```
py -m pip install pyinstaller
py -m PyInstaller --clean --onefile --windowed --add-data "fox.ico;." --noconsole --icon="fox.ico" fox.py

```

The output executable is written to `dist\fox.exe`.


## Notes

- FOX encrypts/decrypts synchronously, so the UI will appear to freeze while
  processing very large files or folders — this is expected.
- There is no password recovery. If you forget the password, the file or
  folder cannot be restored.
