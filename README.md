# ClipFixSynergy

Fixes broken image clipboard transfers from macOS to Windows when using Synergy 3.

Adds PNG and JPEG formats to the Windows clipboard when Synergy only provides DIB, improving compatibility with browsers and apps like ChatGPT upload fields.

---

## Quick Start

### 1. Build

```
dotnet build -c Release
```

> Tip: Install dotnet if you don't have it.
>   `winget install -e --id Microsoft.DotNet.SDK.8`

### 2. Run

GUI only mode:

```
dotnet run -c Release
```

Or run compiled binary:

```
bin\Release\net8.0-windows\ClipFixSynergy.exe
```



Debug mode with logs:

```
dotnet run -c Debug -- --debug
```

Or run compiled binary:

```
bin\Debug\net8.0-windows\ClipFixSynergy.exe
```

The app runs in the system tray.

Blue = running  
Yellow = processing  
Green = success  
Red = error  
Gray = paused  

---

## What Problem Does This Solve?

When copying screenshots from macOS to Windows using Synergy:

- Pasting into Paint works
- Pasting into browsers may show:
  - Broken colors
  - Corrupted image
  - Upload failure

Root cause:  
Synergy often sends only CF_DIB / CF_DIBV5 bitmap formats, without PNG or JPEG clipboard formats. Some Windows apps decode the DIB incorrectly.

ClipFixSynergy:

- Detects Synergy-origin clipboard content
- Decodes the DIB safely
- Re-injects:
  - PNG
  - image/png
  - JFIF
  - image/jpeg
- Adds a done marker to avoid loops

---

## Detecting Original macOS Capture Mode

The app now includes a heuristic to infer whether the screenshot was taken as PNG or JPG on macOS.

It does not detect file format directly, because Synergy sends bitmap data only.

Instead, it inspects:

- Bits per pixel
- Compression type
- Header size vs actual pixel offset

Heuristic rules:

- 32bpp + BI_BITFIELDS + header mismatch → likely PNG pipeline
- 24bpp + BI_RGB + consistent header → likely JPG pipeline

The detected source hint appears in logs and tray status.

---

## Advanced Debug Mode

Enable deep inspection:

```
dotnet run -c Debug -- ^
  --debug ^
  --advdebug ^
  --hexdump --hexdump-bytes=256 ^
  --tag=mac_png ^
  --dumpdir=C:\Users\Gabriel\Projects\Labs\ClipFixSynergy\tmp ^
  --dump-outputs=1 ^
  --fp-bytes=262144 ^
  --pixel-sample=256 ^
  --alpha-sample=16384 ^
  --jpegq=100
```

This will:

- Dump original DIB
- Dump generated PNG/JPEG
- Generate SHA1 fingerprints
- Sample alpha channel
- Log structural differences

---

## How To Generate Controlled macOS Test Captures

Use fixed region capture for reproducibility.

PNG:

```
screencapture -x -t png -R 200,200,800,400 -c
```

JPEG:

```
screencapture -x -t jpg -R 200,200,800,400 -c
```

This copies directly to clipboard and triggers Synergy transfer.

Run once with:

```
--tag=mac_png
```

Then again with:

```
--tag=mac_jpg
```

You can then zip the dump folder and compare both pipelines.

---

## Running With or Without Console

This project is configured to build two variants automatically:

- Debug: console app (OutputType=Exe)
- Release: tray-only app (OutputType=WinExe)

Build:

```
dotnet build -c Debug
dotnet build -c Release
```

Run:

```
dotnet run -c Debug -- --debug
dotnet run -c Release
```

Executable outputs:

```
bin\Debug\net8.0-windows\ClipFixSynergy.exe
bin\Release\net8.0-windows\ClipFixSynergy.exe
```

---

## Prevent Multiple Instances

The app detects if another instance is already running.

If so, it shows:

"ClipFixSynergy is already running."

And exits.

---

## Install To Start With Windows

### Option 1: Startup Folder

Press Win + R:

```
shell:startup
```

Create shortcut to:

```
ClipFixSynergy.exe
```

### Option 2: Task Scheduler

Create new task:

- Trigger: At log on
- Action: Start program
- Program path: full path to ClipFixSynergy.exe

---

## Why This Exists

<details>
<summary>Technical Deep Dive</summary>

The original issue:

Clipboard images transferred from macOS to Windows via Synergy appeared corrupted in browsers but worked in Paint.

Investigation revealed:

- Synergy provides CF_DIB / CF_DIBV5
- Sometimes BI_BITFIELDS with inconsistent header size
- No PNG or JPEG formats provided
- Some decoders misinterpret stride or masks

We confirmed:

- macOS PNG capture produces 32bpp BI_BITFIELDS with header mismatch
- macOS JPG capture produces 24bpp BI_RGB with consistent header
- After conversion and re-injection of PNG/JPEG formats, browser compatibility is restored

ClipFixSynergy acts as a normalization layer on Windows.

</details>

---

## License

MIT

---

## Contributing

Feel free to open issues or submit improvements.

If you are reporting a Synergy-related issue, include:

- DIB dump
- Generated PNG and JPG
- Log file
- Screenshot of paste result
- macOS capture command used

---

## Final Notes

This tool was created as a investigation into a clipboard interoperability issue between macOS and Windows using Synergy.

It can also serve as a clipboard diagnostic tool for advanced debugging of image transfer pipelines.
