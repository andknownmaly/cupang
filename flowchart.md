# Red Team XSS Suite v3.0 - Workflow Flowchart

```mermaid
graph TD
    %% Starting Point
    Start([User Input: Target URL & Args]) --> Init[Initialize Scanner Session]
    Init --> Discovery{Arg: --crawl?}

    %% Phase 1: Discovery
    Discovery -- Yes --> DeepCrawl[Recursive Discovery: Find all internal links]
    Discovery -- No --> ShallowCrawl[Shallow Discovery: Extract links & forms from target page only]
    
    DeepCrawl --> TargetList[Generate Scan Queue]
    ShallowCrawl --> TargetList

    %% Phase 2: Analysis Loop
    TargetList --> ForEachURL{For Each URL}
    
    subgraph "Surgical Analysis Phase"
        ForEachURL --> Extractor[Extract Forms, URL Params, Hidden Params]
        Extractor --> JSAnalysis[Deep Static JS Analysis: Source-to-Sink Mapping]
        Extractor --> ContextProfiling[Context Profiling: Send Canary String]
        
        ContextProfiling --> ContextID{Identify Context}
        ContextID -- HTML --> MapH[Map Tag-based Payloads]
        ContextID -- Attribute --> MapA[Map Quote-breaking Payloads]
        ContextID -- Script --> MapS[Map JS-breakout Payloads]
    end

    %% Phase 3: Attack & Bypass
    subgraph "Exploitation Phase (Multithreaded)"
        MapH --> BypassGen[BypassGenerator: Apply Mutations]
        MapA --> BypassGen
        MapS --> BypassGen
        
        BypassGen --> Mutate[Mutations: Case Scramble, Unicode, Entity Enc, Nesting]
        Mutate --> Execute[Execute Injections: GET/POST Requests]
    end

    %% Phase 4: Validation
    Execute --> Validator{Vulnerability Detected?}
    Validator -- Yes --> POC[Generate Automatic PoC & Evidence]
    Validator -- No --> Next[Move to next injection point]
    
    POC --> Report[Store in Vulnerability Database]
    Next --> ForEachURL

    %% Phase 5: Reporting
    ForEachURL -- All URLS Done --> FinalSummary[Final Summary & Stats]
    FinalSummary --> SaveFile[Save Report: TXT/JSON/HTML]
    SaveFile --> End([End Scan])

    %% Styling
    style Start fill:#f96,stroke:#333,stroke-width:2px
    style End fill:#f96,stroke:#333,stroke-width:2px
    style POC fill:#f00,stroke:#333,stroke-width:2px,color:#fff
    style JSAnalysis fill:#00f,stroke:#333,stroke-width:2px,color:#fff
    style ContextProfiling fill:#0f0,stroke:#333,stroke-width:2px
```

## Deskripsi Alur Kerja (Professional Grade)

### 1. Discovery (Fase Pengintaian)
*   **Shallow Crawl (Default)**: Menganalisis endpoint tunggal untuk mengekstraksi semua form, parameter tersembunyi, dan link `<a>` yang ada pada halaman tersebut.
*   **Deep Crawl (`--crawl`)**: Penelusuran rekursif menyeluruh untuk memetakan seluruh arsitektur website target.

### 2. Surgical Analysis (Fase Pembedahan)
*   **Static JS Analysis**: Secara otomatis mendownload file JavaScript untuk melacak aliran data dari *Sources* user ke *Sinks* berbahaya (DOM XSS).
*   **Context Profiling**: Teknik pengiriman string "canary" untuk mengidentifikasi filter server dan konteks refleksi secara presisi (HTML, Atribut, atau Script).

### 3. Exploitation (Fase Penyerangan)
*   **BypassGenerator**: Inti dari fitur "Overpower" yang melakukan mutasi payload secara dinamis (Unicode, Entity Encoding, Case Scrambling).
*   **Recursive Nesting**: Teknik pembungkusan payload (seperti `<scr<script>ipt>`) untuk menembus filter pembersihan string yang tidak sempurna.

### 4. Validation & Reporting (Fase Pelaporan)
*   **Evidence Collection**: Menangkap potongan kode HTML yang membuktikan eksekusi script.
*   **PoC Generator**: Menghasilkan link exploit atau form simulasi yang siap digunakan dalam laporan audit profesional.
