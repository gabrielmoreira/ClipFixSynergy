using ThreadingTimer = System.Threading.Timer;

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

static class AppInfo
{
  public const string Name = "ClipFixSynergy";
  public static string Version =>
    Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0.0";
}

static class Log
{
  public static bool DebugEnabled = false;
  public static string? LogFilePath = null;

  public static void Info(string msg) => Write("INFO", msg);

  public static void Debug(string msg)
  {
    if (!DebugEnabled) return;
    Write("DEBUG", msg);
  }

  public static void Error(string msg) => Write("ERROR", msg);

  private static void Write(string level, string msg)
  {
    string line = $"[{DateTime.Now:HH:mm:ss.fff}] {level} {msg}";
    Console.WriteLine(line);

    if (!string.IsNullOrWhiteSpace(LogFilePath))
    {
      try { File.AppendAllText(LogFilePath, line + Environment.NewLine); }
      catch { }
    }
  }
}

static class Win32
{
  public const int WM_CLIPBOARDUPDATE = 0x031D;

  public const uint CF_DIB = 8;
  public const uint CF_DIBV5 = 17;

  public const uint GMEM_MOVEABLE = 0x0002;

  [DllImport("user32.dll", SetLastError = true)] public static extern bool AddClipboardFormatListener(IntPtr hwnd);
  [DllImport("user32.dll", SetLastError = true)] public static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern uint RegisterClipboardFormatW([MarshalAs(UnmanagedType.LPWStr)] string name);

  [DllImport("user32.dll", SetLastError = true)] public static extern bool OpenClipboard(IntPtr owner);
  [DllImport("user32.dll", SetLastError = true)] public static extern bool CloseClipboard();
  [DllImport("user32.dll", SetLastError = true)] public static extern bool EmptyClipboard();

  [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr GetClipboardData(uint format);
  [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr SetClipboardData(uint format, IntPtr hMem);

  [DllImport("user32.dll", SetLastError = true)] public static extern uint EnumClipboardFormats(uint format);
  [DllImport("user32.dll", SetLastError = true)] public static extern int GetClipboardFormatNameW(uint format, char[] name, int maxCount);

  [DllImport("kernel32.dll", SetLastError = true)] public static extern UIntPtr GlobalSize(IntPtr hMem);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GlobalLock(IntPtr hMem);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GlobalUnlock(IntPtr hMem);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);

  [DllImport("kernel32.dll")] public static extern uint GetLastError();

  [DllImport("user32.dll", SetLastError = true)] public static extern bool DestroyIcon(IntPtr hIcon);

  public static string? GetFormatName(uint fmt)
  {
    var buf = new char[256];
    int n = GetClipboardFormatNameW(fmt, buf, buf.Length);
    if (n <= 0) return null;
    return new string(buf, 0, n);
  }

  public static byte[] ReadGlobalBytes(IntPtr hMem)
  {
    ulong size = (ulong)GlobalSize(hMem);
    if (size == 0) return Array.Empty<byte>();

    IntPtr p = GlobalLock(hMem);
    if (p == IntPtr.Zero) return Array.Empty<byte>();

    try
    {
      var data = new byte[size];
      Marshal.Copy(p, data, 0, (int)size);
      return data;
    }
    finally { GlobalUnlock(hMem); }
  }

  public static IntPtr AllocGlobalFromBytes(byte[] data)
  {
    IntPtr h = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)data.Length);
    if (h == IntPtr.Zero) return IntPtr.Zero;

    IntPtr p = GlobalLock(h);
    if (p == IntPtr.Zero) return IntPtr.Zero;

    try { Marshal.Copy(data, 0, p, data.Length); }
    finally { GlobalUnlock(h); }

    return h;
  }
}

sealed class ClipboardListenerWindow : NativeWindow, IDisposable
{
  public event Action? ClipboardUpdated;

  public ClipboardListenerWindow()
  {
    CreateHandle(new CreateParams());
    Win32.AddClipboardFormatListener(Handle);
  }

  protected override void WndProc(ref Message m)
  {
    if (m.Msg == Win32.WM_CLIPBOARDUPDATE)
      ClipboardUpdated?.Invoke();

    base.WndProc(ref m);
  }

  public void Dispose()
  {
    try { Win32.RemoveClipboardFormatListener(Handle); } catch { }
    DestroyHandle();
  }
}

sealed class Options
{
  public bool Debug { get; set; } = false;
  public string? LogFile { get; set; }

  public int ScheduleDelayMs { get; set; } = 500;

  public int OpenAttempts { get; set; } = 30;
  public int OpenDelayMs { get; set; } = 50;

  public int DibAttempts { get; set; } = 30;
  public int DibDelayMs { get; set; } = 100;

  public bool TrimEnabled { get; set; } = true;
  public int AlphaThreshold { get; set; } = 1;

  // Set default to 100 as requested
  public long JpegQuality { get; set; } = 100;

  public bool HexDumpEnabled { get; set; } = false;
  public int HexDumpBytes { get; set; } = 96;

  // Advanced debug / experiments
  public bool AdvancedDebug { get; set; } = false;
  public string Tag { get; set; } = "";
  public string? DumpDir { get; set; } = @"C:\Users\Gabriel\Projects\Labs\ClipFixSynergy\tmp";
  public bool DumpOutputs { get; set; } = false;
  public int FingerprintBytes { get; set; } = 65536;
  public int PixelSampleBytes { get; set; } = 64;
  public int AlphaSamplePixels { get; set; } = 4096;
  public int MaxDumpFilesPerRun { get; set; } = 50;

  // Controls whether we try to guess the origin format (PNG vs JPEG) from DIB characteristics.
  public bool OriginHeuristicEnabled { get; set; } = true;

  public static Options Parse(string[] args)
  {
    var o = new Options();
    foreach (var raw in args)
    {
      var arg = raw.Trim();

      if (arg.Equals("--debug", StringComparison.OrdinalIgnoreCase))
        o.Debug = true;

      else if (arg.StartsWith("--logfile=", StringComparison.OrdinalIgnoreCase))
        o.LogFile = arg.Substring("--logfile=".Length);

      else if (TryParseInt(arg, "--schedule=", out int sched)) o.ScheduleDelayMs = Math.Max(0, sched);

      else if (TryParseInt(arg, "--open-attempts=", out int oa)) o.OpenAttempts = Math.Max(1, oa);
      else if (TryParseInt(arg, "--open-delay=", out int od)) o.OpenDelayMs = Math.Max(0, od);

      else if (TryParseInt(arg, "--dib-attempts=", out int da)) o.DibAttempts = Math.Max(1, da);
      else if (TryParseInt(arg, "--dib-delay=", out int dd)) o.DibDelayMs = Math.Max(0, dd);

      else if (TryParseBool(arg, "--trim=", out bool trim)) o.TrimEnabled = trim;
      else if (TryParseInt(arg, "--alpha=", out int alpha)) o.AlphaThreshold = Math.Max(0, Math.Min(255, alpha));

      else if (TryParseLong(arg, "--jpegq=", out long q)) o.JpegQuality = Math.Max(1, Math.Min(100, q));

      else if (arg.Equals("--hexdump", StringComparison.OrdinalIgnoreCase)) o.HexDumpEnabled = true;
      else if (TryParseInt(arg, "--hexdump-bytes=", out int hb)) o.HexDumpBytes = Math.Max(16, hb);

      else if (arg.Equals("--advdebug", StringComparison.OrdinalIgnoreCase)) o.AdvancedDebug = true;
      else if (arg.StartsWith("--tag=", StringComparison.OrdinalIgnoreCase)) o.Tag = arg.Substring("--tag=".Length).Trim();
      else if (arg.StartsWith("--dumpdir=", StringComparison.OrdinalIgnoreCase)) o.DumpDir = arg.Substring("--dumpdir=".Length).Trim();
      else if (TryParseBool(arg, "--dump-outputs=", out bool dox)) o.DumpOutputs = dox;
      else if (TryParseInt(arg, "--fp-bytes=", out int fp)) o.FingerprintBytes = Math.Max(1024, fp);
      else if (TryParseInt(arg, "--pixel-sample=", out int ps)) o.PixelSampleBytes = Math.Max(16, ps);
      else if (TryParseInt(arg, "--alpha-sample=", out int ap)) o.AlphaSamplePixels = Math.Max(256, ap);
      else if (TryParseInt(arg, "--max-dumps=", out int md)) o.MaxDumpFilesPerRun = Math.Max(1, md);
      else if (TryParseBool(arg, "--origin-heuristic=", out bool oh)) o.OriginHeuristicEnabled = oh;
    }

    return o;
  }

  private static bool TryParseInt(string arg, string prefix, out int value)
  {
    value = 0;
    if (!arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
    return int.TryParse(arg.Substring(prefix.Length), out value);
  }

  private static bool TryParseLong(string arg, string prefix, out long value)
  {
    value = 0;
    if (!arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
    return long.TryParse(arg.Substring(prefix.Length), out value);
  }

  private static bool TryParseBool(string arg, string prefix, out bool value)
  {
    value = false;
    if (!arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;

    var s = arg.Substring(prefix.Length).Trim();
    if (s.Equals("1") || s.Equals("true", StringComparison.OrdinalIgnoreCase) || s.Equals("yes", StringComparison.OrdinalIgnoreCase))
    {
      value = true;
      return true;
    }
    if (s.Equals("0") || s.Equals("false", StringComparison.OrdinalIgnoreCase) || s.Equals("no", StringComparison.OrdinalIgnoreCase))
    {
      value = false;
      return true;
    }
    return false;
  }
}

static class Hex
{
  public static string Dump(byte[] data, int offset, int count)
  {
    if (data.Length == 0) return "<empty>";
    int start = Math.Max(0, offset);
    if (start >= data.Length) return "<offset out of range>";

    int n = Math.Min(count, data.Length - start);
    var sb = new StringBuilder();

    for (int i = 0; i < n; i++)
    {
      if (i % 16 == 0) sb.Append($"{start + i:X4}: ");
      sb.Append(data[start + i].ToString("X2")).Append(' ');
      if (i % 16 == 15 || i == n - 1) sb.AppendLine();
    }

    return sb.ToString();
  }
}

static class CryptoUtil
{
  public static string Sha1Hex(byte[] data, int maxBytes)
  {
    int n = Math.Min(Math.Max(0, maxBytes), data.Length);
    using var sha1 = SHA1.Create();
    byte[] hash = sha1.ComputeHash(data, 0, n);
    var sb = new StringBuilder(hash.Length * 2);
    foreach (byte b in hash) sb.Append(b.ToString("x2"));
    return sb.ToString();
  }
}

enum TrayState
{
  IdleBlue,
  PausedGray,
  ProcessingYellow,
  SuccessGreen,
  ErrorRed
}

sealed class TrayController : IDisposable
{
  private readonly SynchronizationContext _ui;
  private readonly NotifyIcon _tray;

  private readonly Icon _blue;
  private readonly Icon _gray;
  private readonly Icon _yellow;
  private readonly Icon _green;
  private readonly Icon _red;

  private readonly ToolStripMenuItem _titleItem;
  private readonly ToolStripMenuItem _pauseResumeItem;
  private readonly ToolStripMenuItem _exitItem;

  private bool _paused = false;

  public event Action<bool>? PauseChanged;

  public TrayController(SynchronizationContext ui)
  {
    _ui = ui;

    _blue = Tray_CreateDotIcon(Color.DeepSkyBlue);
    _gray = Tray_CreateDotIcon(Color.Gray);
    _yellow = Tray_CreateDotIcon(Color.Gold);
    _green = Tray_CreateDotIcon(Color.LimeGreen);
    _red = Tray_CreateDotIcon(Color.IndianRed);

    var menu = new ContextMenuStrip();

    _titleItem = new ToolStripMenuItem($"{AppInfo.Name} v{AppInfo.Version}")
    {
      Enabled = false
    };

    _pauseResumeItem = new ToolStripMenuItem("Pause");
    _pauseResumeItem.Click += (_, __) => TogglePause();

    _exitItem = new ToolStripMenuItem("Exit");
    _exitItem.Click += (_, __) => Application.Exit();

    menu.Items.Add(_titleItem);
    menu.Items.Add(new ToolStripSeparator());
    menu.Items.Add(_pauseResumeItem);
    menu.Items.Add(new ToolStripSeparator());
    menu.Items.Add(_exitItem);

    _tray = new NotifyIcon
    {
      Icon = _blue,
      Visible = true,
      ContextMenuStrip = menu
    };

    Set(TrayState.IdleBlue, $"{AppInfo.Name} - Running");
  }

  private void TogglePause()
  {
    _paused = !_paused;

    _ui.Post(_ =>
    {
      _pauseResumeItem.Text = _paused ? "Resume" : "Pause";
      PauseChanged?.Invoke(_paused);
    }, null);
  }

  public void Set(TrayState state, string text)
  {
    _ui.Post(_ =>
    {
      _tray.Icon = state switch
      {
        TrayState.PausedGray => _gray,
        TrayState.ProcessingYellow => _yellow,
        TrayState.SuccessGreen => _green,
        TrayState.ErrorRed => _red,
        _ => _blue
      };

      _tray.Text = Tray_Truncate(text, 63);
    }, null);
  }

  public void Dispose()
  {
    _ui.Post(_ =>
    {
      _tray.Visible = false;
      _tray.Dispose();
      _blue.Dispose();
      _gray.Dispose();
      _yellow.Dispose();
      _green.Dispose();
      _red.Dispose();
    }, null);
  }

  private static string Tray_Truncate(string s, int max)
  {
    if (string.IsNullOrEmpty(s)) return AppInfo.Name;
    if (s.Length <= max) return s;
    if (max <= 3) return s.Substring(0, max);
    return s.Substring(0, max - 3) + "...";
  }

  private static Icon Tray_CreateDotIcon(Color color)
  {
    using var bmp = new Bitmap(16, 16, PixelFormat.Format32bppArgb);
    using (var g = Graphics.FromImage(bmp))
    {
      g.Clear(Color.Transparent);
      g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

      using var b = new SolidBrush(color);
      g.FillEllipse(b, 2, 2, 12, 12);
      g.DrawEllipse(Pens.Black, 2, 2, 12, 12);
    }

    IntPtr hIcon = bmp.GetHicon();
    try
    {
      using var tmp = Icon.FromHandle(hIcon);
      return (Icon)tmp.Clone();
    }
    finally
    {
      Win32.DestroyIcon(hIcon);
    }
  }
}

sealed class ClipFixEngine : IDisposable
{
  private readonly Options _opt;
  private readonly Action<TrayState, string> _tray;
  private readonly ThreadingTimer _timer;
  private int _pending = 0;
  private readonly object _lock = new object();

  private volatile bool _paused = false;

  private int _dumpCount = 0;

  public void SetPaused(bool paused)
  {
    _paused = paused;

    if (paused)
    {
      Log.Info("Paused.");
      _tray(TrayState.PausedGray, $"{AppInfo.Name} - Paused");
    }
    else
    {
      Log.Info("Resumed.");
      _tray(TrayState.IdleBlue, $"{AppInfo.Name} - Running");
    }
  }

  public ClipFixEngine(Options opt, Action<TrayState, string> traySetter)
  {
    _opt = opt;
    _tray = traySetter;
    _timer = new ThreadingTimer(_ => RunOnce(), null, Timeout.Infinite, Timeout.Infinite);
  }

  public void Schedule()
  {
    if (_paused) return;
    if (Interlocked.Exchange(ref _pending, 1) == 1) return;
    _timer.Change(_opt.ScheduleDelayMs, Timeout.Infinite);
  }

  private void RunOnce()
  {
    if (_paused)
    {
      Interlocked.Exchange(ref _pending, 0);
      return;
    }

    Interlocked.Exchange(ref _pending, 0);

    lock (_lock)
    {
      Log.Debug("RunOnce triggered");

      var res = Clipboard_ProcessOnce(_opt, onProcessingStart: () =>
      {
        _tray(TrayState.ProcessingYellow, $"{AppInfo.Name} - Processing...");
      });

      // Do not overwrite last good state when we skip because of done marker.
      if (res.Kind == ResultKind.Skipped)
      {
        if (res.Message.Contains("done marker", StringComparison.OrdinalIgnoreCase))
          return;

        _tray(TrayState.IdleBlue, $"{AppInfo.Name} - Skipped ({res.Message})");
        return;
      }

      string t = DateTime.Now.ToString("HH:mm:ss");

      if (res.Kind == ResultKind.Success)
      {
        _tray(TrayState.SuccessGreen, $"{res.PrimaryLabel} {res.SizeLabel} {res.DimLabel} {t}");
        if (!string.IsNullOrWhiteSpace(res.Hint))
          Log.Info($"Source hint: {res.Hint}");
        return;
      }

      _tray(TrayState.ErrorRed, $"ERR {t} {res.Message}");
      if (!string.IsNullOrWhiteSpace(res.Hint))
        Log.Info($"Source hint: {res.Hint}");
    }
  }

  public void Dispose() => _timer.Dispose();

  enum ResultKind { Skipped, Success, Error }

  sealed class ProcessResult
  {
    public ResultKind Kind { get; }
    public string Message { get; }
    public string Hint { get; }

    // For tray tooltip
    public string PrimaryLabel { get; }
    public string SizeLabel { get; }
    public string DimLabel { get; }

    private ProcessResult(
      ResultKind kind,
      string message,
      string hint,
      string primaryLabel,
      string sizeLabel,
      string dimLabel)
    {
      Kind = kind;
      Message = message;
      Hint = hint;
      PrimaryLabel = primaryLabel;
      SizeLabel = sizeLabel;
      DimLabel = dimLabel;
    }

    public static ProcessResult Skipped(string message, string hint = "")
      => new ProcessResult(ResultKind.Skipped, message, hint, "", "", "");

    public static ProcessResult Error(string message, string hint = "")
      => new ProcessResult(ResultKind.Error, message, hint, "", "", "");

    public static ProcessResult Success(string primary, string size, string dim, string hint)
      => new ProcessResult(ResultKind.Success, "success", hint, primary, size, dim);
  }


  private sealed class ProcessContext
  {
    public readonly Options Opt;

    public readonly uint CfPng = Win32.RegisterClipboardFormatW("PNG");
    public readonly uint CfImagePng = Win32.RegisterClipboardFormatW("image/png");
    public readonly uint CfJfif = Win32.RegisterClipboardFormatW("JFIF");
    public readonly uint CfImageJpeg = Win32.RegisterClipboardFormatW("image/jpeg");
    public readonly uint CfDone = Win32.RegisterClipboardFormatW("ClipFixDone");
    public readonly uint CfSynergyOwnership = Win32.RegisterClipboardFormatW("SynergyOwnership");

    public HashSet<uint> Formats = new HashSet<uint>();
    public byte[] DibBytes = Array.Empty<byte>();
    public DibHeader DibHeader;

    public int DerivedStride;
    public int DerivedPixelOffset;

    public Bitmap? Decoded;

    public byte[] PngBytes = Array.Empty<byte>();
    public byte[] JpegBytes = Array.Empty<byte>();

    public ProcessContext(Options opt)
    {
      Opt = opt;
      DibHeader = default;
    }
  }

  private ProcessResult Clipboard_ProcessOnce(Options opt, Action onProcessingStart)
  {
    var ctx = new ProcessContext(opt);

    if (!Clipboard_TryOpenWithRetry(ctx, phase: "A"))
      return ProcessResult.Skipped("OpenClipboard failed");

    string formatPresenceHint = "Source formats present: unknown";
    try
    {
      ctx.Formats = Clipboard_EnumerateFormats();
      Log.Debug($"Formats count: {ctx.Formats.Count}");
      Log.Debug($"SynergyOwnership registered id: {ctx.CfSynergyOwnership}");

      if (opt.Debug)
      {
        foreach (var f in ctx.Formats)
        {
          var name = Win32.GetFormatName(f);
          Log.Debug($"Format: {f} Name: {name ?? "(standard or name unavailable)"}");
        }
      }

      bool hasDone = ctx.Formats.Contains(ctx.CfDone);
      if (hasDone) return ProcessResult.Skipped("done marker present");

      bool hasSynergy = ctx.Formats.Contains(ctx.CfSynergyOwnership);
      if (!hasSynergy) return ProcessResult.Skipped("SynergyOwnership not present");

      bool hasDib = ctx.Formats.Contains(Win32.CF_DIB) || ctx.Formats.Contains(Win32.CF_DIBV5);
      if (!hasDib) return ProcessResult.Skipped("no DIB present");

      bool srcHadPng = ctx.Formats.Contains(ctx.CfPng) || ctx.Formats.Contains(ctx.CfImagePng);
      bool srcHadJpeg = ctx.Formats.Contains(ctx.CfJfif) || ctx.Formats.Contains(ctx.CfImageJpeg);

      if (srcHadPng && srcHadJpeg) formatPresenceHint = "Source formats present: PNG and JPEG";
      else if (srcHadPng) formatPresenceHint = "Source formats present: PNG";
      else if (srcHadJpeg) formatPresenceHint = "Source formats present: JPEG";
      else formatPresenceHint = "Source formats present: none (bitmap only)";

      if (srcHadPng) return ProcessResult.Skipped("PNG already present", formatPresenceHint);
    }
    catch (Exception ex)
    {
      Log.Error($"Phase A exception: {ex.Message}");
      return ProcessResult.Error($"phase A: {ex.Message}", formatPresenceHint);
    }
    finally
    {
      Win32.CloseClipboard();
    }

    onProcessingStart();

    IntPtr hDib = Clipboard_TryGetDibHandleWithReopen(ctx);
    if (hDib == IntPtr.Zero)
      return ProcessResult.Error("failed to obtain DIB handle", formatPresenceHint);

    if (!Clipboard_TryOpenWithRetry(ctx, phase: "C"))
      return ProcessResult.Error("OpenClipboard failed (phase C)", formatPresenceHint);

    try
    {
      byte[] synergyOwnershipBytes = Array.Empty<byte>();
      try
      {
        IntPtr hOwn = Win32.GetClipboardData(ctx.CfSynergyOwnership);
        if (hOwn != IntPtr.Zero)
          synergyOwnershipBytes = Win32.ReadGlobalBytes(hOwn);
      }
      catch { }

      IntPtr h = Win32.GetClipboardData(Win32.CF_DIBV5);
      if (h == IntPtr.Zero) h = Win32.GetClipboardData(Win32.CF_DIB);
      if (h == IntPtr.Zero)
        return ProcessResult.Error("GetClipboardData returned NULL", formatPresenceHint);

      ctx.DibBytes = Win32.ReadGlobalBytes(h);
      Log.Debug($"Read DIB bytes: {ctx.DibBytes.Length}");
      if (ctx.DibBytes.Length == 0)
        return ProcessResult.Error("DIB bytes empty", formatPresenceHint);

      ctx.DibHeader = Dib_ReadHeader(ctx.DibBytes);
      Log.Debug($"DIB header: biSize={ctx.DibHeader.Size} w={ctx.DibHeader.Width} h={ctx.DibHeader.HeightSigned} planes={ctx.DibHeader.Planes} bpp={ctx.DibHeader.Bpp} compression={ctx.DibHeader.Compression} clrUsed={ctx.DibHeader.ClrUsed}");

      bool hasPixelInfo = Dib_TryDerivePixelOffset(ctx, out int stride, out int pixelOffset);
      if (hasPixelInfo)
      {
        ctx.DerivedStride = stride;
        ctx.DerivedPixelOffset = pixelOffset;
        Log.Debug($"Derived stride={stride}, pixelOffset={pixelOffset}");

        if (opt.HexDumpEnabled)
        {
          int around = Math.Max(0, pixelOffset - 32);
          Log.Debug("Hex around pixel offset:\n" + Hex.Dump(ctx.DibBytes, around, opt.HexDumpBytes));
        }
      }
      else
      {
        Log.Debug("Could not derive pixel offset (will still attempt GDI+ decode).");
      }

      // Advanced debug: fingerprint + optional dumps
      if (opt.AdvancedDebug)
      {
        string tag = string.IsNullOrWhiteSpace(opt.Tag) ? "" : $" tag='{opt.Tag}'";
        string sha1 = CryptoUtil.Sha1Hex(ctx.DibBytes, opt.FingerprintBytes);
        Log.Info($"AdvDebug:{tag} dibLen={ctx.DibBytes.Length} fpBytes={Math.Min(opt.FingerprintBytes, ctx.DibBytes.Length)} sha1={sha1}");

        if (hasPixelInfo)
        {
          int sampleN = Math.Min(opt.PixelSampleBytes, Math.Max(0, ctx.DibBytes.Length - pixelOffset));
          if (sampleN > 0)
            Log.Info($"AdvDebug:{tag} pixelSample at offset={pixelOffset} bytes={sampleN}\n{Hex.Dump(ctx.DibBytes, pixelOffset, sampleN)}");

          if (ctx.DibHeader.Bpp == 32)
          {
            var a = Dib_AlphaSampleFromDib(ctx.DibBytes, ctx.DibHeader, stride, pixelOffset, opt.AlphaSamplePixels);
            Log.Info($"AdvDebug:{tag} dibAlphaSample: samples={a.Samples} alpha!=255={a.NonOpaque} alpha==0={a.ZeroAlpha}");
          }
        }

        if (!string.IsNullOrWhiteSpace(opt.DumpDir) && _dumpCount < opt.MaxDumpFilesPerRun)
          TryDumpOriginalDib(opt, ctx, formatPresenceHint);
      }

      // Decode
      try
      {
        ctx.Decoded = Dib_DecodeWithGdiPlus(ctx.DibBytes, ctx.DibHeader);
      }
      catch (Exception ex)
      {
        Log.Debug($"GDI+ DIB decode failed: {ex.Message}. Trying 32bpp fallback...");
        if (!hasPixelInfo)
        {
          if (!Dib_TryDerivePixelOffset(ctx, out stride, out pixelOffset))
            return ProcessResult.Error("decode failed and could not derive pixel offset", formatPresenceHint);

          ctx.DerivedStride = stride;
          ctx.DerivedPixelOffset = pixelOffset;
          hasPixelInfo = true;
        }

        try
        {
          ctx.Decoded = Dib_Decode32bppFallback(ctx.DibBytes, ctx.DibHeader, stride, pixelOffset);
          Log.Info("Fallback 32bpp DIB decode succeeded.");
        }
        catch (Exception ex2)
        {
          return ProcessResult.Error($"fallback decode failed: {ex2.Message}", formatPresenceHint);
        }
      }

      if (ctx.Decoded == null)
        return ProcessResult.Error("decode produced null bitmap", formatPresenceHint);

      using (ctx.Decoded)
      {
        Log.Info($"Decoded bitmap: {ctx.Decoded.Width}x{ctx.Decoded.Height}, PixelFormat={ctx.Decoded.PixelFormat}");

        using var argb = Img_ToArgb(ctx.Decoded);

        Bitmap final = argb;
        if (opt.TrimEnabled && opt.AlphaThreshold > 0)
        {
          var trimmed = Img_TrimTransparent(argb, (byte)opt.AlphaThreshold);
          if (trimmed.Width == argb.Width && trimmed.Height == argb.Height)
          {
            trimmed.Dispose();
          }
          else
          {
            final = trimmed;
          }
        }

        using (final)
        {
          Log.Info($"Final bitmap: {final.Width}x{final.Height} (trim={opt.TrimEnabled}, alpha={opt.AlphaThreshold})");

          bool hasAnyAlpha = Img_HasAnyTransparencySampled(final, opt.AlphaSamplePixels);

          // Encode outputs we inject
          try
          {
            ctx.PngBytes = Enc_EncodePng(final);

            using var jpg = Img_FlattenTo24bppWhite(final);
            ctx.JpegBytes = Enc_EncodeJpeg(jpg, opt.JpegQuality);
          }
          catch (Exception ex)
          {
            return ProcessResult.Error($"encode failed: {ex.Message}", formatPresenceHint);
          }

          Log.Info($"Generated PNG ({ctx.PngBytes.Length} bytes) and JPEG ({ctx.JpegBytes.Length} bytes).");

          // Origin format heuristic (what Synergy likely originated from on macOS)
          string originGuess = "ORIG ?";
          string originReason = "No heuristic applied";

          if (opt.OriginHeuristicEnabled)
          {
            var guess = OriginHeuristic.GuessFromDib(ctx.DibHeader, hasAnyAlpha, ctx.DibBytes.Length, hasPixelInfo ? ctx.DerivedPixelOffset : 0);
            originGuess = guess.Label;
            originReason = guess.Reason;
          }

          // Rewrite clipboard
          if (!Clipboard_TryEmptyWithRetry(ctx))
            return ProcessResult.Error("EmptyClipboard failed", formatPresenceHint);

          // Preserve SynergyOwnership (helps avoid resync weirdness)
          if (synergyOwnershipBytes.Length > 0)
          {
            var hOwnNew = Win32.AllocGlobalFromBytes(synergyOwnershipBytes);
            if (hOwnNew != IntPtr.Zero) Win32.SetClipboardData(ctx.CfSynergyOwnership, hOwnNew);
          }
          else
          {
            var hOwnMin = Win32.AllocGlobalFromBytes(new byte[] { 1 });
            if (hOwnMin != IntPtr.Zero) Win32.SetClipboardData(ctx.CfSynergyOwnership, hOwnMin);
          }

          // Provide a stable CF_DIB for consumers
          byte[] dibFixed = Dib_BuildCfDib32bppTopDown(final);
          var hDibNew = Win32.AllocGlobalFromBytes(dibFixed);
          if (hDibNew == IntPtr.Zero)
            return ProcessResult.Error("AllocGlobalFromBytes(DIB) failed", formatPresenceHint);
          if (Win32.SetClipboardData(Win32.CF_DIB, hDibNew) == IntPtr.Zero)
            return ProcessResult.Error("SetClipboardData(CF_DIB) failed", formatPresenceHint);

          // Add PNG and JPEG formats for browser compatibility
          var hPngNew = Win32.AllocGlobalFromBytes(ctx.PngBytes);
          if (hPngNew == IntPtr.Zero)
            return ProcessResult.Error("AllocGlobalFromBytes(PNG) failed", formatPresenceHint);
          if (Win32.SetClipboardData(ctx.CfPng, hPngNew) == IntPtr.Zero)
            return ProcessResult.Error("SetClipboardData(PNG) failed", formatPresenceHint);

          var hImgPng = Win32.AllocGlobalFromBytes(ctx.PngBytes);
          if (hImgPng != IntPtr.Zero) Win32.SetClipboardData(ctx.CfImagePng, hImgPng);

          var hJfif = Win32.AllocGlobalFromBytes(ctx.JpegBytes);
          if (hJfif != IntPtr.Zero) Win32.SetClipboardData(ctx.CfJfif, hJfif);

          var hImgJpeg = Win32.AllocGlobalFromBytes(ctx.JpegBytes);
          if (hImgJpeg != IntPtr.Zero) Win32.SetClipboardData(ctx.CfImageJpeg, hImgJpeg);

          var hDone = Win32.AllocGlobalFromBytes(new byte[] { 1 });
          if (hDone != IntPtr.Zero) Win32.SetClipboardData(ctx.CfDone, hDone);

          Log.Info("Clipboard correction applied.");

          if (opt.AdvancedDebug && opt.DumpOutputs && !string.IsNullOrWhiteSpace(opt.DumpDir) && _dumpCount < opt.MaxDumpFilesPerRun)
            TryDumpOutputs(opt, ctx, dibFixed);

          string alphaHint = hasAnyAlpha ? "Alpha detected (not JPEG)" : "No alpha detected";
          string contentHint = (ctx.JpegBytes.Length > 0 && ctx.PngBytes.Length > 0)
            ? (ctx.JpegBytes.Length < ctx.PngBytes.Length ? "Content leans photo-like (JPEG smaller)" : "Content leans screenshot-like (PNG smaller)")
            : "Content hint unavailable";

          string fullHint = $"{formatPresenceHint}; {alphaHint}; {contentHint}; Origin={originGuess} ({originReason})";

          // Tray wants: origin format and size corresponding to that origin guess
          long chosenBytes = originGuess.Contains("JPG", StringComparison.OrdinalIgnoreCase) ? ctx.JpegBytes.Length : ctx.PngBytes.Length;
          string sizeLabel = Fmt_FormatBytes(chosenBytes);
          string dimLabel = $"{final.Width}x{final.Height}";

          return ProcessResult.Success(originGuess, sizeLabel, dimLabel, fullHint);
        }
      }
    }
    catch (Exception ex)
    {
      Log.Error($"Processing exception: {ex.Message}");
      return ProcessResult.Error(ex.Message, formatPresenceHint);
    }
    finally
    {
      Win32.CloseClipboard();
    }
  }

  // ---------- Origin heuristic ----------
  private static class OriginHeuristic
  {
    public readonly struct Guess
    {
      public readonly string Label;
      public readonly string Reason;
      public Guess(string label, string reason) { Label = label; Reason = reason; }
    }

    // Based on your captured samples: mac 'png' tended to arrive as 32bpp BI_BITFIELDS, pixelOffset small (40),
    // while mac 'jpg' tended to arrive as 24bpp BI_RGB, pixelOffset 124, no alpha.
    public static Guess GuessFromDib(DibHeader h, bool hasAnyAlpha, int dibLen, int pixelOffset)
    {
      // Strong signal: real alpha means not JPEG origin.
      if (hasAnyAlpha)
        return new Guess("ORIG PNG", "Alpha channel detected");

      // Strong signal from header pattern we observed.
      if (h.Bpp == 24 && h.Compression == 0 && h.Size == 124 && pixelOffset >= 100)
        return new Guess("ORIG JPG", "24bpp BI_RGB with large header region (typical of JPEG capture path)");

      if (h.Bpp == 32 && (h.Compression == 3 || h.Compression == 6))
        return new Guess("ORIG PNG", "32bpp with BITFIELDS compression (typical of PNG capture path)");

      // If bpp is 32 but no alpha observed, still more PNG-like in our tests.
      if (h.Bpp == 32)
        return new Guess("ORIG PNG", "32bpp bitmap path with no alpha observed (still more PNG-like)");

      // Otherwise unknown, pick a safe default label.
      return new Guess("ORIG ?", "Insufficient distinguishing signals");
    }
  }

  // ---------- Advanced debug dump helpers ----------
  private void TryDumpOriginalDib(Options opt, ProcessContext ctx, string sourceFormatHint)
  {
    try
    {
      Directory.CreateDirectory(opt.DumpDir!);

      string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
      string tag = string.IsNullOrWhiteSpace(opt.Tag) ? "" : $"_{Sanitize(opt.Tag)}";
      string meta = $"_{ctx.DibHeader.Width}x{Math.Abs(ctx.DibHeader.HeightSigned)}_bpp{ctx.DibHeader.Bpp}_c{ctx.DibHeader.Compression}_hsz{ctx.DibHeader.Size}";
      string baseName = $"dib{tag}_{ts}{meta}";

      string path = Path.Combine(opt.DumpDir!, baseName + ".bin");
      File.WriteAllBytes(path, ctx.DibBytes);

      _dumpCount++;
      Log.Info($"AdvDebug: dumped original DIB to '{path}' ({ctx.DibBytes.Length} bytes). SourceHint='{sourceFormatHint}'.");
    }
    catch (Exception ex)
    {
      Log.Error($"AdvDebug: dump original DIB failed: {ex.Message}");
    }
  }

  private void TryDumpOutputs(Options opt, ProcessContext ctx, byte[] dibFixed)
  {
    try
    {
      Directory.CreateDirectory(opt.DumpDir!);

      string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
      string tag = string.IsNullOrWhiteSpace(opt.Tag) ? "" : $"_{Sanitize(opt.Tag)}";
      string baseName = $"out{tag}_{ts}";

      string p1 = Path.Combine(opt.DumpDir!, baseName + ".png");
      string p2 = Path.Combine(opt.DumpDir!, baseName + ".jpg");
      string p3 = Path.Combine(opt.DumpDir!, baseName + "_fixed_cf_dib.bin");

      File.WriteAllBytes(p1, ctx.PngBytes);
      File.WriteAllBytes(p2, ctx.JpegBytes);
      File.WriteAllBytes(p3, dibFixed);

      _dumpCount++;
      Log.Info($"AdvDebug: dumped outputs to '{p1}', '{p2}', '{p3}'.");
    }
    catch (Exception ex)
    {
      Log.Error($"AdvDebug: dump outputs failed: {ex.Message}");
    }
  }

  private static string Sanitize(string s)
  {
    if (string.IsNullOrEmpty(s)) return "";
    var sb = new StringBuilder(s.Length);
    foreach (char c in s)
    {
      if (char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.') sb.Append(c);
      else sb.Append('_');
    }
    return sb.ToString();
  }

  // ---------- Clipboard helpers ----------
  private static bool Clipboard_TryOpenWithRetry(ProcessContext ctx, string phase)
  {
    for (int i = 0; i < ctx.Opt.OpenAttempts; i++)
    {
      if (Win32.OpenClipboard(IntPtr.Zero)) return true;
      Thread.Sleep(ctx.Opt.OpenDelayMs);
    }
    Log.Debug($"OpenClipboard failed (phase {phase}) after retries.");
    return false;
  }

  private static bool Clipboard_TryEmptyWithRetry(ProcessContext ctx)
  {
    for (int i = 0; i < 10; i++)
    {
      if (Win32.EmptyClipboard()) return true;

      uint err = Win32.GetLastError();
      Log.Debug($"EmptyClipboard failed (attempt {i + 1}/10), LastError={err}");

      Win32.CloseClipboard();
      Thread.Sleep(50);

      if (!Clipboard_TryOpenWithRetry(ctx, phase: "EmptyRetry"))
        continue;
    }
    return false;
  }

  private static HashSet<uint> Clipboard_EnumerateFormats()
  {
    var set = new HashSet<uint>();
    uint fmt = 0;
    while (true)
    {
      fmt = Win32.EnumClipboardFormats(fmt);
      if (fmt == 0) break;
      set.Add(fmt);
    }
    return set;
  }

  private static IntPtr Clipboard_TryGetDibHandleWithReopen(ProcessContext ctx)
  {
    uint fmt1 = Win32.CF_DIBV5;
    uint fmt2 = Win32.CF_DIB;

    for (int i = 0; i < ctx.Opt.DibAttempts; i++)
    {
      if (!Win32.OpenClipboard(IntPtr.Zero))
      {
        Thread.Sleep(ctx.Opt.DibDelayMs);
        continue;
      }

      try
      {
        IntPtr h1 = Win32.GetClipboardData(fmt1);
        if (h1 != IntPtr.Zero) return h1;

        IntPtr h2 = Win32.GetClipboardData(fmt2);
        if (h2 != IntPtr.Zero) return h2;

        uint err = Win32.GetLastError();
        Log.Debug($"Attempt {i + 1}/{ctx.Opt.DibAttempts}: GetClipboardData returned NULL. LastError={err}");
      }
      finally
      {
        Win32.CloseClipboard();
      }

      Thread.Sleep(ctx.Opt.DibDelayMs);
    }

    return IntPtr.Zero;
  }

  // ---------- DIB ----------
  private readonly struct DibHeader
  {
    public readonly int Size;
    public readonly int Width;
    public readonly int HeightSigned;
    public readonly short Planes;
    public readonly short Bpp;
    public readonly int Compression;
    public readonly int ClrUsed;

    public DibHeader(int size, int width, int heightSigned, short planes, short bpp, int compression, int clrUsed)
    {
      Size = size;
      Width = width;
      HeightSigned = heightSigned;
      Planes = planes;
      Bpp = bpp;
      Compression = compression;
      ClrUsed = clrUsed;
    }
  }

  private static DibHeader Dib_ReadHeader(byte[] dib)
  {
    if (dib.Length < 40) throw new Exception("DIB too small");

    int biSize = BitConverter.ToInt32(dib, 0);
    int biWidth = BitConverter.ToInt32(dib, 4);
    int biHeight = BitConverter.ToInt32(dib, 8);
    short planes = BitConverter.ToInt16(dib, 12);
    short bpp = BitConverter.ToInt16(dib, 14);
    int compression = BitConverter.ToInt32(dib, 16);
    int clrUsed = BitConverter.ToInt32(dib, 32);

    return new DibHeader(biSize, biWidth, biHeight, planes, bpp, compression, clrUsed);
  }

  private static int Dib_StrideBytes(int width, int bitsPerPixel)
  {
    int bytesPerLine = (width * bitsPerPixel + 7) / 8;
    return (bytesPerLine + 3) & ~3;
  }

  private static bool Dib_TryDerivePixelOffset(ProcessContext ctx, out int stride, out int pixelOffset)
  {
    stride = Dib_StrideBytes(ctx.DibHeader.Width, ctx.DibHeader.Bpp);
    int height = Math.Abs(ctx.DibHeader.HeightSigned);

    long pixelsBytes = (long)stride * height;
    long off = (long)ctx.DibBytes.Length - pixelsBytes;

    if (off < 0 || off > int.MaxValue)
    {
      pixelOffset = 0;
      return false;
    }

    pixelOffset = (int)off;
    return true;
  }

  private static Bitmap Dib_DecodeWithGdiPlus(byte[] dib, DibHeader h)
  {
    int paletteEntries = 0;
    if (h.Bpp <= 8)
      paletteEntries = h.ClrUsed != 0 ? h.ClrUsed : (1 << h.Bpp);

    int paletteSize = paletteEntries * 4;

    int bitfieldsMaskSize = 0;
    const int BI_BITFIELDS = 3;
    const int BI_ALPHABITFIELDS = 6;
    if (h.Size == 40 && (h.Compression == BI_BITFIELDS || h.Compression == BI_ALPHABITFIELDS))
      bitfieldsMaskSize = 12;

    int bfOffBits = 14 + h.Size + bitfieldsMaskSize + paletteSize;
    int bfSize = 14 + dib.Length;

    byte[] bmpFile = new byte[bfSize];

    bmpFile[0] = (byte)'B';
    bmpFile[1] = (byte)'M';
    BitConverter.GetBytes(bfSize).CopyTo(bmpFile, 2);
    BitConverter.GetBytes(bfOffBits).CopyTo(bmpFile, 10);
    Buffer.BlockCopy(dib, 0, bmpFile, 14, dib.Length);

    MemoryStream ms = new MemoryStream(bmpFile, writable: false);
    Bitmap? tmp = null;

    try
    {
      tmp = new Bitmap(ms);
      _ = tmp.Width;
      _ = tmp.Height;
      _ = tmp.PixelFormat;
      return new Bitmap(tmp);
    }
    finally
    {
      tmp?.Dispose();
      ms.Dispose();
    }
  }

  private static Bitmap Dib_Decode32bppFallback(byte[] dib, DibHeader h, int stride, int pixelOffset)
  {
    if (h.Bpp != 32) throw new Exception($"Fallback supports only 32bpp, got {h.Bpp}");
    if (h.Width <= 0) throw new Exception("Invalid width");

    int height = Math.Abs(h.HeightSigned);
    if (height <= 0) throw new Exception("Invalid height");

    long required = (long)pixelOffset + (long)stride * height;
    if (required > dib.Length) throw new Exception("DIB buffer too small for pixels");

    bool topDown = h.HeightSigned < 0;

    uint rMask = 0x00FF0000, gMask = 0x0000FF00, bMask = 0x000000FF, aMask = 0xFF000000;

    bool headerHasMasks = pixelOffset >= 56 && dib.Length >= 56;
    if (headerHasMasks)
    {
      rMask = BitConverter.ToUInt32(dib, 40);
      gMask = BitConverter.ToUInt32(dib, 44);
      bMask = BitConverter.ToUInt32(dib, 48);
      aMask = BitConverter.ToUInt32(dib, 52);

      if (rMask == 0 && gMask == 0 && bMask == 0)
      {
        rMask = 0x00FF0000; gMask = 0x0000FF00; bMask = 0x000000FF; aMask = 0xFF000000;
      }
    }

    (int rShift, int rBits) = Dib_MaskShiftBits(rMask);
    (int gShift, int gBits) = Dib_MaskShiftBits(gMask);
    (int bShift, int bBits) = Dib_MaskShiftBits(bMask);
    (int aShift, int aBits) = Dib_MaskShiftBits(aMask);

    var bmp = new Bitmap(h.Width, height, PixelFormat.Format32bppArgb);
    var rect = new Rectangle(0, 0, h.Width, height);
    var data = bmp.LockBits(rect, ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);

    try
    {
      int dstStride = data.Stride;

      unsafe
      {
        fixed (byte* pSrcBase = dib)
        {
          byte* dstBase = (byte*)data.Scan0.ToPointer();

          for (int y = 0; y < height; y++)
          {
            int sy = topDown ? y : (height - 1 - y);
            byte* srcRow = pSrcBase + pixelOffset + sy * stride;
            byte* dstRow = dstBase + y * dstStride;

            for (int x = 0; x < h.Width; x++)
            {
              uint px = *(uint*)(srcRow + x * 4);

              byte r = Dib_Extract(px, rMask, rShift, rBits);
              byte g = Dib_Extract(px, gMask, gShift, gBits);
              byte b = Dib_Extract(px, bMask, bShift, bBits);

              byte a;
              if (aMask == 0 || aBits == 0) a = 255;
              else
              {
                a = Dib_Extract(px, aMask, aShift, aBits);
                if (a == 0) a = 255;
              }

              int di = x * 4;
              dstRow[di + 0] = b;
              dstRow[di + 1] = g;
              dstRow[di + 2] = r;
              dstRow[di + 3] = a;
            }
          }
        }
      }
    }
    finally
    {
      bmp.UnlockBits(data);
    }

    return bmp;
  }

  private static (int shift, int bits) Dib_MaskShiftBits(uint mask)
  {
    if (mask == 0) return (0, 0);

    int shift = 0;
    while (shift < 32 && ((mask >> shift) & 1) == 0) shift++;

    int bits = 0;
    while ((shift + bits) < 32 && ((mask >> (shift + bits)) & 1) == 1) bits++;

    return (shift, bits);
  }

  private static byte Dib_Extract(uint px, uint mask, int shift, int bits)
  {
    if (mask == 0 || bits == 0) return 0;

    uint v = (px & mask) >> shift;
    if (bits == 8) return (byte)v;

    uint max = (uint)((1 << bits) - 1);
    return (byte)((v * 255u) / max);
  }

  private readonly struct AlphaSample
  {
    public readonly int Samples;
    public readonly int NonOpaque;
    public readonly int ZeroAlpha;

    public AlphaSample(int samples, int nonOpaque, int zeroAlpha)
    {
      Samples = samples;
      NonOpaque = nonOpaque;
      ZeroAlpha = zeroAlpha;
    }
  }

  private static AlphaSample Dib_AlphaSampleFromDib(byte[] dib, DibHeader h, int stride, int pixelOffset, int maxSamples)
  {
    int w = h.Width;
    int height = Math.Abs(h.HeightSigned);
    if (w <= 0 || height <= 0) return new AlphaSample(0, 0, 0);
    if (h.Bpp != 32) return new AlphaSample(0, 0, 0);

    long needed = (long)pixelOffset + (long)stride * height;
    if (needed > dib.Length) return new AlphaSample(0, 0, 0);

    int totalPixels = w * height;
    int samples = Math.Min(maxSamples, totalPixels);
    if (samples <= 0) return new AlphaSample(0, 0, 0);

    int step = Math.Max(1, totalPixels / samples);

    int nonOpaque = 0;
    int zeroAlpha = 0;

    for (int idx = 0, taken = 0; idx < totalPixels && taken < samples; idx += step, taken++)
    {
      int y = idx / w;
      int x = idx - (y * w);

      int rowOff = pixelOffset + y * stride;
      int pxOff = rowOff + x * 4;
      if (pxOff + 3 >= dib.Length) break;

      byte a = dib[pxOff + 3];
      if (a != 255) nonOpaque++;
      if (a == 0) zeroAlpha++;
    }

    return new AlphaSample(samples, nonOpaque, zeroAlpha);
  }

  // ---------- Image transforms ----------
  private static Bitmap Img_ToArgb(Bitmap src)
  {
    var dst = new Bitmap(src.Width, src.Height, PixelFormat.Format32bppArgb);
    using (var g = Graphics.FromImage(dst))
    {
      g.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
      g.DrawImage(src, 0, 0);
    }
    return dst;
  }

  private static Bitmap Img_TrimTransparent(Bitmap srcArgb, byte alphaThreshold)
  {
    var rect = new Rectangle(0, 0, srcArgb.Width, srcArgb.Height);
    var data = srcArgb.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);

    byte[] bytes;
    int stride;
    try
    {
      stride = data.Stride;
      int total = Math.Abs(stride) * srcArgb.Height;
      bytes = new byte[total];
      Marshal.Copy(data.Scan0, bytes, 0, total);
    }
    finally
    {
      srcArgb.UnlockBits(data);
    }

    int w = srcArgb.Width;
    int h = srcArgb.Height;
    int minX = w, minY = h, maxX = -1, maxY = -1;
    int strideAbs = Math.Abs(stride);

    for (int y = 0; y < h; y++)
    {
      int row = y * strideAbs;
      for (int x = 0; x < w; x++)
      {
        byte a = bytes[row + x * 4 + 3];
        if (a >= alphaThreshold)
        {
          if (x < minX) minX = x;
          if (y < minY) minY = y;
          if (x > maxX) maxX = x;
          if (y > maxY) maxY = y;
        }
      }
    }

    if (maxX < minX || maxY < minY)
      return new Bitmap(1, 1, PixelFormat.Format32bppArgb);

    int outW = (maxX - minX) + 1;
    int outH = (maxY - minY) + 1;

    var dst = new Bitmap(outW, outH, PixelFormat.Format32bppArgb);
    using (var g = Graphics.FromImage(dst))
    {
      g.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
      g.DrawImage(srcArgb,
        new Rectangle(0, 0, outW, outH),
        new Rectangle(minX, minY, outW, outH),
        GraphicsUnit.Pixel);
    }

    return dst;
  }

  private static Bitmap Img_FlattenTo24bppWhite(Bitmap srcArgb)
  {
    var dst = new Bitmap(srcArgb.Width, srcArgb.Height, PixelFormat.Format24bppRgb);
    using (var g = Graphics.FromImage(dst))
    {
      g.Clear(Color.White);
      g.DrawImage(srcArgb, 0, 0);
    }
    return dst;
  }

  private static bool Img_HasAnyTransparencySampled(Bitmap srcArgb, int maxSamples)
  {
    var rect = new Rectangle(0, 0, srcArgb.Width, srcArgb.Height);
    var data = srcArgb.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);

    try
    {
      int stride = data.Stride;
      int w = srcArgb.Width;
      int h = srcArgb.Height;
      int totalPixels = w * h;
      int samples = Math.Min(Math.Max(256, maxSamples), totalPixels);
      int step = Math.Max(1, totalPixels / samples);

      unsafe
      {
        byte* basePtr = (byte*)data.Scan0.ToPointer();
        for (int idx = 0, taken = 0; idx < totalPixels && taken < samples; idx += step, taken++)
        {
          int y = idx / w;
          int x = idx - (y * w);
          byte* row = basePtr + y * stride;
          byte a = row[x * 4 + 3];
          if (a != 255) return true;
        }
      }

      return false;
    }
    finally
    {
      srcArgb.UnlockBits(data);
    }
  }

  // ---------- Encoders ----------
  private static byte[] Enc_EncodePng(Bitmap bmp)
  {
    using var ms = new MemoryStream();
    bmp.Save(ms, ImageFormat.Png);
    return ms.ToArray();
  }

  private static byte[] Enc_EncodeJpeg(Bitmap bmp, long quality)
  {
    using var ms = new MemoryStream();
    var enc = Enc_GetEncoder(ImageFormat.Jpeg);
    using var ep = new EncoderParameters(1);
    ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, quality);
    bmp.Save(ms, enc, ep);
    return ms.ToArray();
  }

  private static ImageCodecInfo Enc_GetEncoder(ImageFormat fmt)
  {
    foreach (var c in ImageCodecInfo.GetImageEncoders())
      if (c.FormatID == fmt.Guid) return c;
    throw new Exception("JPEG encoder not found");
  }

  // ---------- Formatting ----------
  private static string Fmt_FormatBytes(long bytes)
  {
    if (bytes < 1024) return $"{bytes} B";
    double kb = bytes / 1024.0;
    if (kb < 1024.0) return $"{kb:0.0} KB";
    double mb = kb / 1024.0;
    return $"{mb:0.0} MB";
  }

  // ---------- Build CF_DIB ----------
  private static byte[] Dib_BuildCfDib32bppTopDown(Bitmap srcArgb)
  {
    using var bmp = Img_ToArgb(srcArgb);

    int w = bmp.Width;
    int h = bmp.Height;

    const int BI_RGB = 0;
    int headerSize = 40;
    int stride = w * 4;
    int pixelBytes = stride * h;

    var dib = new byte[headerSize + pixelBytes];

    BitConverter.GetBytes(headerSize).CopyTo(dib, 0);
    BitConverter.GetBytes(w).CopyTo(dib, 4);
    BitConverter.GetBytes(-h).CopyTo(dib, 8);
    BitConverter.GetBytes((short)1).CopyTo(dib, 12);
    BitConverter.GetBytes((short)32).CopyTo(dib, 14);
    BitConverter.GetBytes(BI_RGB).CopyTo(dib, 16);
    BitConverter.GetBytes(pixelBytes).CopyTo(dib, 20);

    var rect = new Rectangle(0, 0, w, h);
    var data = bmp.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
    try
    {
      int srcStride = data.Stride;
      int dstOff = headerSize;

      unsafe
      {
        byte* srcBase = (byte*)data.Scan0.ToPointer();
        for (int y = 0; y < h; y++)
        {
          byte* srcRow = srcBase + y * srcStride;
          Marshal.Copy((IntPtr)srcRow, dib, dstOff, stride);
          dstOff += stride;
        }
      }
    }
    finally
    {
      bmp.UnlockBits(data);
    }

    return dib;
  }
}

sealed class TrayAppContext : ApplicationContext
{
  private readonly ClipboardListenerWindow _listener;
  private readonly TrayController _tray;
  private readonly ClipFixEngine _engine;

  public TrayAppContext(Options opt)
  {
    var ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

    _tray = new TrayController(ui);
    _tray.Set(TrayState.IdleBlue, $"{AppInfo.Name} - Running");

    _engine = new ClipFixEngine(opt, (state, text) => _tray.Set(state, text));

    _tray.PauseChanged += paused =>
    {
      _engine.SetPaused(paused);
      if (!paused)
        _tray.Set(TrayState.IdleBlue, $"{AppInfo.Name} - Running");
    };

    _listener = new ClipboardListenerWindow();
    _listener.ClipboardUpdated += () =>
    {
      Log.Debug("WM_CLIPBOARDUPDATE received");
      _engine.Schedule();
    };
  }

  protected override void ExitThreadCore()
  {
    _listener.Dispose();
    _engine.Dispose();
    _tray.Dispose();
    base.ExitThreadCore();
  }
}

static class Program
{
  [STAThread]
  static void Main(string[] args)
  {
    // Single instance guard
    bool createdNew = false;
    using var mutex = new Mutex(true, @"Global\ClipFixSynergy_SingleInstance", out createdNew);
    if (!createdNew)
    {
      try
      {
        MessageBox.Show(
          $"{AppInfo.Name} is already running.",
          AppInfo.Name,
          MessageBoxButtons.OK,
          MessageBoxIcon.Information
        );
      }
      catch { }
      return;
    }

    var opt = Options.Parse(args);

    Log.DebugEnabled = opt.Debug;
    Log.LogFilePath = opt.LogFile;

    Log.Info($"{AppInfo.Name} started (v{AppInfo.Version})");
    Log.Info($"Debug: {opt.Debug}");
    Log.Info($"Trim: {opt.TrimEnabled}, AlphaThreshold: {opt.AlphaThreshold}, JpegQuality: {opt.JpegQuality}");
    Log.Info($"ScheduleDelayMs: {opt.ScheduleDelayMs}");
    Log.Info($"OpenAttempts: {opt.OpenAttempts}, OpenDelayMs: {opt.OpenDelayMs}, DibAttempts: {opt.DibAttempts}, DibDelayMs: {opt.DibDelayMs}");
    if (!string.IsNullOrWhiteSpace(opt.LogFile)) Log.Info($"Log file: {opt.LogFile}");
    if (opt.HexDumpEnabled) Log.Info($"Hexdump enabled: {opt.HexDumpBytes} bytes");

    if (opt.AdvancedDebug)
    {
      Log.Info("Advanced debug enabled.");
      Log.Info($"AdvDebug: tag='{opt.Tag}', dumpDir='{opt.DumpDir}', dumpOutputs={opt.DumpOutputs}, fpBytes={opt.FingerprintBytes}, pixelSample={opt.PixelSampleBytes}, alphaSample={opt.AlphaSamplePixels}, maxDumps={opt.MaxDumpFilesPerRun}, originHeuristic={opt.OriginHeuristicEnabled}");
    }

    Application.EnableVisualStyles();
    Application.SetCompatibleTextRenderingDefault(false);
    Application.Run(new TrayAppContext(opt));
  }
}
