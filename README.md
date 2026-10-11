# GNIT CyberSec C Lab V6

Features:
- Student registration -> login
- Admin login
- Persistent local JSON database (`server/data.json`)
- Monaco C editor
- VS Code-style terminal: click Run, then type input line-by-line and press Enter
- Program output appears automatically in the terminal
- GCC compiler errors are shown in red in the terminal and as red editor markers
- Submit with hidden test cases
- Student progress and submission history
- Admin can see student submissions/code and send feedback
- Admin can add/delete problems
- Server binds to `0.0.0.0` so LAN IPs can be used

## Run on Windows

Open VS Code terminal:

```powershell
cd server
npm install
node server.js
```

Then open:
http://localhost:3000

Admin demo:
- username: `admin`
- password: `admin123`

Students can create their own accounts from "Create Student Account".

## LAN access

When the server starts it prints addresses such as:
`http://192.168.x.x:3000`

Other devices on the same network can use that address. Windows Firewall may ask for permission.

## Important

This is a prototype. It executes arbitrary C code on the host machine. Do NOT expose this directly to the public internet without a proper sandbox/container, resource limits, authentication hardening, HTTPS, and a production database.

The "Run" terminal is a real child process with stdin/stdout streaming, so input can be entered interactively.
