# ClipFixSynergy

Adds PNG and JPEG formats to the Windows clipboard when Synergy 3 only provides DIB, improving compatibility with browsers and apps such as ChatGPT upload fields.

---

## Download

Prebuilt binaries are available in the **Releases** section:

https://github.com/gabrielmoreira/ClipFixSynergy/releases

Download the latest:

ClipFixSynergy-x.y.z-win-x64.zip

Extract and run `ClipFixSynergy.exe`.

No installation required.

---

## Quick Start

Run the executable.

The app runs in the system tray.

Status colors:

Blue = running  
Yellow = processing  
Green = success  
Red = error  
Gray = paused  

That’s it.

---

## What Problem Does This Solve?

When copying screenshots from macOS to Windows using Synergy:

- Pasting into Paint works
- Pasting into browsers may show:
  - Broken colors
  - Corrupted image
  - Upload failure

Root cause:

Synergy often sends only CF_DIB / CF_DIBV5 bitmap formats without PNG or JPEG clipboard formats.

Some Windows apps decode these DIB structures incorrectly.

This issue was observed with Synergy 3.x (tested on 3.5.1). Behavior may vary in other versions.

ClipFixSynergy:

- Detects Synergy-origin clipboard content
- Safely decodes the DIB
- Re-injects:
  - PNG
  - image/png
  - JFIF
  - image/jpeg
- Adds a done marker to prevent processing loops

This restores compatibility with modern applications.

---

## Detecting Original macOS Capture Mode

Synergy transfers bitmap data only.

The original file format is not directly available.

The app attempts to infer whether the macOS screenshot was PNG or JPG by inspecting:

- Bits per pixel
- Compression type
- Header size vs derived pixel offset

Heuristic observations:

- 32bpp + BI_BITFIELDS + header mismatch → likely PNG pipeline
- 24bpp + BI_RGB + consistent header → likely JPG pipeline

The detected hint appears in logs and tray status.

This is heuristic, not guaranteed.

---

## Advanced Debug Mode

For deep inspection:

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

This enables:

- Original DIB dump
- Generated PNG/JPEG dump
- SHA1 fingerprinting
- Alpha sampling
- Structural comparison

Useful when investigating Synergy behavior differences.

---

## Controlled macOS Test Captures

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

Tag runs separately:

```
--tag=mac_png
```

```
--tag=mac_jpg
```

You can then zip the dump folder and compare both pipelines.

---

## Build From Source

Requires .NET 8 SDK.

Install if needed:

```
winget install -e --id Microsoft.DotNet.SDK.8
```

Build:

```
dotnet build -c Release
```

Debug build:

```
dotnet build -c Debug
```

Release builds produce a tray-only executable.  
Debug builds include console output.

---

## Start With Windows

Option 1: Startup folder

Press Win + R:

```
shell:startup
```

Create a shortcut to `ClipFixSynergy.exe`.

Option 2: Task Scheduler

- Trigger: At log on
- Action: Start program
- Program path: Full path to ClipFixSynergy.exe

---

## Technical Deep Dive

<details>
<summary>Expand technical investigation details</summary>

The original issue:

Clipboard images transferred from macOS to Windows via Synergy appeared corrupted in browsers but worked in Paint.

Investigation revealed:

- Synergy provides CF_DIB / CF_DIBV5
- Sometimes BI_BITFIELDS with inconsistent header structure
- No PNG or JPEG formats provided
- Some decoders misinterpret stride or masks

We confirmed:

- macOS PNG capture produces 32bpp BI_BITFIELDS with header/pixel offset mismatch
- macOS JPG capture produces 24bpp BI_RGB with consistent header
- After conversion and re-injection of PNG/JPEG formats, browser compatibility is restored

ClipFixSynergy acts as a normalization layer on Windows.

</details>

---

## License

MIT

---

## Contributing

If reporting a Synergy-related issue, include:

- DIB dump
- Generated PNG and JPG
- Log file
- Screenshot of paste result
- macOS capture command used

---

## Final Notes

This tool was created during a deep investigation into clipboard interoperability issues between macOS and Windows using Synergy.

It can also serve as a diagnostic tool for advanced clipboard debugging.
