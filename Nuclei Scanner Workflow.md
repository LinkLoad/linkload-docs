# Nuclei Scanner Workflow 

## Overview
This document provides a complete, step-by-step explanation of how the Nuclei scanner works in the LinkLoad application - from the moment a user initiates a scan to when results appear on the frontend dashboard.

---

## PART 1: SCAN INITIATION (Frontend → Backend)

### Step 1: User Initiates Scan from Frontend
**Location**: Frontend Dashboard/Scanner Interface

```jsx
// User clicks "Start Scan" button
// Frontend sends HTTP POST request to backend API
```

**What happens**: User enters target URL (e.g., `https://example.com`) and selects scan options:
- Scan type: `nuclei` (or multiple scanners)
- Deep scan (yes/no)
- Custom options
- Scan mode (quick/standard/deep)

---

### Step 2: API Endpoint Receives Request
**File**: [linkload-core/app/api/scans.py](linkload-core/app/api/scans.py#L144)

```python
@router.post("/comprehensive/start", response_model=StartScanResponse)
async def start_comprehensive_scan(
    request: StartScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user)
):
    """
    Step 2.1: Validate User
    - Ensure user is authenticated
    - Extract user_id for ownership tracking
    """
    user_id = get_user_id(current_user)  # Gets authenticated user from JWT token
    
    """
    Step 2.2: Generate Unique Scan ID
    - Creates a unique identifier for this scan run
    - Format: "scan_" + 12-character hex string
    - Example: "scan_a1b2c3d4e5f6"
    """
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    
    """
    Step 2.3: Create Initial Scan Record in Database
    - Stores scan metadata in Supabase
    - Status starts as "pending"
    - Progress initially 0%
    """
    scan_record = {
        "scan_id": scan_id,
        "user_id": user_id,  # For ownership verification
        "target_url": str(request.target_url),  # e.g., "https://example.com"
        "scan_types": request.scan_types,  # ["nuclei", ...other scanners]
        "status": "pending",  # Starting status
        "progress": 0,
        "current_stage": "Initializing",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "options": request.options.dict()  # Scan configuration
    }
    
    # Database Call
    supabase.create_scan(scan_record)
    
    """
    Step 2.4: Queue Background Scan Task
    - Instead of running scan synchronously (blocking),
      we queue it to run in the background
    - FastAPI's BackgroundTasks handles this
    - Function runs asynchronously in a worker thread
    """
    background_tasks.add_task(
        _run_comprehensive_scan_sync,
        scan_id,
        str(request.target_url),
        request.scan_types,
        request.options.dict(),
        user_id
    )
    
    """
    Step 2.5: Return Scan ID to Frontend
    - Frontend receives scan_id immediately
    - Client can now poll for status or connect to WebSocket
    """
    return StartScanResponse(
        scan_id=scan_id,
        status_url=f"/api/v1/scans/comprehensive/{scan_id}/status"
    )
```

**Database State After Step 2**:
```
Supabase Table: scans
┌────────────────────┬───────────────────────────────────┐
│ scan_id            │ scan_a1b2c3d4e5f6                 │
│ user_id            │ user_12345                        │
│ target_url         │ https://example.com               │
│ status             │ pending                           │
│ progress           │ 0                                 │
│ current_stage      │ Initializing                      │
│ started_at         │ 2024-01-31T10:30:00Z              │
│ scan_types         │ ["nuclei", "owasp", "wapiti"]    │
└────────────────────┴───────────────────────────────────┘
```

---

## PART 2: COMPREHENSIVE SCANNER ORCHESTRATION

### Step 3: Background Task Starts
**File**: [linkload-core/app/api/scans.py](linkload-core/app/api/scans.py#L1000+)

The `_run_comprehensive_scan_sync()` function is called by the background task:

```python
def _run_comprehensive_scan_sync(
    scan_id: str,
    target_url: str,
    scan_types: List[str],  # ["nuclei", "owasp", "wapiti"]
    options: Dict[str, Any],
    user_id: str
):
    """
    This function runs in a background worker thread
    It wraps async calls and manages the entire scan lifecycle
    """
    
    # Step 3.1: Get event loop for async operations
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Step 3.2: Call async scanner
        loop.run_until_complete(
            _run_comprehensive_scan_async(
                scan_id,
                target_url,
                scan_types,
                options,
                user_id
            )
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        # Update database with error status
        supabase.update_scan(scan_id, {
            "status": "failed",
            "error": str(e)
        })
    finally:
        loop.close()
```

---

### Step 4: Comprehensive Scanner Initialization
**File**: [linkload-core/app/services/comprehensive_scanner.py](linkload-core/app/services/comprehensive_scanner.py#L47)

```python
class ComprehensiveScanner:
    """
    This class orchestrates ALL scanners in the system
    During initialization, it detects which scanners are available
    """
    
    def __init__(self):
        """Initialize scanner components"""
        self.scanners = {}  # Dictionary to hold Scanner instances
        self._initialize_scanners()
    
    def _initialize_scanners(self):
        """
        Step 4.1: Scanner Detection and Initialization
        
        For NUCLEI Scanner:
        """
        
        # Check if Nuclei should run in Docker mode or locally
        nuclei_use_docker = os.getenv("NUCLEI_USE_DOCKER", "").lower() in ("true", "1", "yes")
        nuclei_container = os.getenv("NUCLEI_CONTAINER", "linkload-nuclei")
        
        from app.services.scanners.nuclei_scanner import NucleiScanner, NucleiScannerConfig
        
        if nuclei_use_docker:
            """
            DOCKER MODE:
            - Nuclei runs inside a Docker container
            - Backend communicates via docker exec commands
            - Better isolation and consistency across environments
            """
            try:
                # Test if Docker container is available
                result = subprocess.run(
                    ['docker', 'exec', nuclei_container, 'nuclei', '-version'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    nuclei_config = NucleiScannerConfig()
                    nuclei_scanner = NucleiScanner(nuclei_config)
                    available_scanners["nuclei"] = nuclei_scanner
                    logger.info(f"[OK] Nuclei scanner initialized (Docker: {nuclei_container})")
                else:
                    logger.warning(f"[WARN] Nuclei container not available")
            except Exception as e:
                logger.warning(f"[WARN] Docker mode failed: {e}")
        else:
            """
            LOCAL BINARY MODE:
            - Nuclei runs as a local binary on the same machine
            - Must be installed via: apt-get install nuclei (or similar)
            - Or downloaded from: https://github.com/projectdiscovery/nuclei
            """
            nuclei_binary = "nuclei"  # Assumed to be in PATH
            nuclei_config = NucleiScannerConfig(binary_path=nuclei_binary)
            nuclei_scanner = NucleiScanner(nuclei_config)
            
            # Verify binary exists and works
            try:
                result = subprocess.run(
                    [nuclei_binary, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    available_scanners["nuclei"] = nuclei_scanner
                    logger.info("[OK] Nuclei scanner initialized (Local binary)")
            except Exception:
                logger.warning("[WARN] Nuclei binary not available")
```

---

## PART 3: NUCLEI SCANNER EXECUTION

### Step 5: Nuclei Scan Starts
**File**: [linkload-core/app/services/scanners/nuclei_scanner.py](linkload-core/app/services/scanners/nuclei_scanner.py#L47)

#### Step 5.1: NucleiScanner Class Initialization

```python
class NucleiScanner(BaseScanner):
    """
    This is the main Nuclei scanner implementation
    It handles all Nuclei-specific operations
    """
    
    def __init__(self, config: Optional[NucleiScannerConfig] = None):
        """
        Step 5.1: Initialize Nuclei Configuration
        """
        # Load configuration (scan parameters)
        self.config = config or NucleiScannerConfig()
        
        # Configuration details:
        # rate_limit: 150 (requests per second - balances speed vs target load)
        # concurrency: 25 (parallel template execution)
        # timeout: 10 (seconds per request)
        # retries: 2 (retry failed requests)
        # update_templates: True (get latest vulnerability signatures)
        # deep_scan: False (default - can be overridden)
        
        # Determine execution mode
        self.use_docker = _is_docker_mode()  # Check NUCLEI_USE_DOCKER env var
        self.docker_container = _get_nuclei_container()  # Get container name
        
        # Active scans tracking (in case multiple scans run simultaneously)
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        
        # Thread pool for blocking operations (like subprocess calls)
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Windows subprocess compatibility flag
        self.is_windows = sys.platform == 'win32' and not self.use_docker
        
        logger.info(f"NucleiScanner initialized (mode: {'docker' if self.use_docker else 'local'})")
```

---

#### Step 5.2: Scan Configuration Building

```python
async def start_scan(self, config: ScannerConfig) -> str:
    """
    Step 5.2: Build and Execute Nuclei Command
    
    This is where the actual Nuclei scan is configured and started
    """
    
    scan_id = str(uuid.uuid4())  # Unique ID for THIS scan run
    
    # Step 5.2.1: Prepare Output Directory
    if self.use_docker:
        # Docker mode: output goes to container's /shared volume
        output_dir = f"/shared/nuclei_results_{scan_id}"
        results_file = f"{output_dir}/results.jsonl"
        
        # Create directory in container
        mkdir_result = await asyncio.get_event_loop().run_in_executor(
            self.executor,
            lambda: subprocess.run(
                ['docker', 'exec', self.docker_container, 'mkdir', '-p', output_dir],
                capture_output=True,
                text=True,
                timeout=10
            )
        )
    else:
        # Local mode: output goes to current working directory
        output_dir = os.path.abspath(os.path.join(os.getcwd(), f"nuclei_results_{scan_id}"))
        results_file = os.path.abspath(os.path.join(output_dir, "results.jsonl"))
        os.makedirs(output_dir, exist_ok=True)
    
    """
    Step 5.2.2: Detect Scan Mode (deep_scan vs normal)
    
    DEEP SCAN MODE:
    - Maximum coverage with reduced speed
    - Tests ALL vulnerability types
    - Lower rate limits (50 req/s instead of 150)
    - Higher concurrency (more parallel workers)
    - Longer timeouts (15s instead of 10s)
    - Includes: DAST, Code scanning, Passive analysis
    - Headless browser enabled (for JS/DOM XSS)
    - ALL severity levels (info, low, medium, high, critical)
    
    STANDARD SCAN MODE (default):
    - Balanced speed and coverage
    - Tests common vulnerabilities
    - Rate limit: 150 req/s
    - Concurrency: 25 workers
    - Timeout: 10s
    - Severity filter: critical, high, medium only
    - Passive + DAST modes
    """
    
    deep_scan = getattr(config, 'deep_scan', False)
    
    if deep_scan:
        rate_limit = 50
        concurrency = max(os.cpu_count() or 4 * 3, 25)  # More workers for parallel work
        retries = 3
        timeout = 15
        max_host_error = 50
        logger.info(f"[Nuclei] DEEP SCAN MODE: max coverage, slower speed")
    else:
        rate_limit = 150
        concurrency = max(os.cpu_count() or 4 * 2, 25)
        retries = 2
        timeout = 10
        max_host_error = 30
        logger.info(f"[Nuclei] STANDARD SCAN MODE: optimized balance")
```

---

#### Step 5.3: Build Nuclei Command Arguments

```python
    """
    Step 5.3: Build Complete Nuclei Command
    
    This builds the actual command that will be executed
    Example: nuclei -u https://example.com -jsonl -o results.jsonl ...
    """
    
    nuclei_args = [
        '-u', config.target_url,  # Target URL
        '-jsonl',  # JSON Lines output format (one JSON object per line)
        '-o', results_file,  # Output file
        '-rl', str(rate_limit),  # Rate limit (requests per second)
        '-c', str(concurrency),  # Concurrency (parallel workers)
        '-retries', str(retries),  # Retry attempts
        '-timeout', str(timeout),  # Request timeout
        '-mhe', str(max_host_error),  # Max host errors before stopping
        '-nc',  # No color codes in output
        '-stats',  # Show real-time statistics
        '-si', '10',  # Stats interval (every 10 seconds)
        '-fr',  # Follow HTTP redirects
        '-fhr',  # Follow host redirects (to different domains)
        '-sresp',  # Store all responses
        '-srd', output_dir,  # Store response directory
        '-silent',  # Quiet output
        '-v',  # Verbose logging
    ]
    
    # Add templates directory if specified
    if self.config.templates_dir:
        nuclei_args.extend(['-templates', self.config.templates_dir])
    
    """
    Step 5.3.1: Deep Scan - All Vulnerabilities
    """
    if deep_scan:
        # Include ALL severity levels
        nuclei_args.extend(['-s', 'critical,high,medium,low,info'])
        
        # Enable DAST (Dynamic Application Security Testing)
        # Actively probes for vulnerabilities
        nuclei_args.append('-dast')
        
        # Enable Code scanning (for source code vulnerabilities)
        nuclei_args.append('-code')
        
        # Passive analysis (non-intrusive detection via HTTP responses)
        nuclei_args.extend(['-passive'])
        
        # Use ALL template categories
        comprehensive_tags = [
            'cve',  # Common Vulnerabilities and Exposures
            'panel',  # Admin panel detection
            'exposure',  # Information disclosure
            'misconfig',  # Security misconfigurations
            'xss',  # Cross-site scripting
            'sqli',  # SQL injection
            'lfi',  # Local file inclusion
            'rce',  # Remote code execution
            'ssrf',  # Server-side request forgery
            'csrf',  # Cross-site request forgery
            'xxe',  # XML external entity
            'idor',  # Insecure direct object reference
            'auth-bypass',  # Authentication bypass
            'redirect',  # Open redirect
            'intrusive',  # Intrusive tests
            'fuzz',  # Fuzzing tests
            'default-login',  # Default credentials
            'token',  # Token exposure
            'tech',  # Technology detection
            'injection',  # All injection types
        ]
        nuclei_args.extend(['-tags', ','.join(comprehensive_tags)])
        
        # Optional: headless browser for JS/DOM vulnerabilities
        if os.getenv('NUCLEI_ENABLE_HEADLESS', '').lower() in ('true', '1'):
            nuclei_args.append('-headless')
            nuclei_args.extend(['-page-timeout', '30'])
        
        logger.info("[Nuclei] Enabled: DAST, code scanning, passive, headless browser")
    
    else:
        """
        Step 5.3.2: Standard Scan - High Value Vulnerabilities
        """
        # High-priority severities only (faster)
        nuclei_args.extend(['-s', 'critical,high,medium'])
        
        # Active scanning
        nuclei_args.append('-dast')
        nuclei_args.extend(['-passive'])
        
        # High-priority templates only
        priority_tags = [
            'cve', 'panel', 'exposure', 'misconfig', 'xss', 
            'sqli', 'rce', 'ssrf', 'lfi', 'auth-bypass', 
            'default-login', 'injection'
        ]
        nuclei_args.extend(['-tags', ','.join(priority_tags)])
        
        # Automatic template selection based on target technology
        nuclei_args.append('-as')
        
        logger.info("[Nuclei] Standard scan: high-priority templates only")
```

---

#### Step 5.4: Execute Nuclei Process

```python
    """
    Step 5.4: Start Nuclei Process
    
    The command is now executed either via Docker or as local binary
    """
    
    if self.use_docker:
        # Docker mode execution
        cmd = ['docker', 'exec', self.docker_container, 'nuclei'] + nuclei_args
        logger.info(f"[Nuclei] Docker command: {' '.join(cmd[:5])}...")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy()
        )
    else:
        # Local binary mode execution
        cmd = [self.config.binary_path] + nuclei_args
        logger.info(f"[Nuclei] Binary command: {cmd[0]} {' '.join(cmd[1:5])}...")
        
        if self.is_windows:
            # Windows subprocess compatibility
            proc = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                lambda: subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=output_dir
                )
            )
        else:
            # Linux/Mac subprocess
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=output_dir
            )
    
    """
    Step 5.5: Store Scan Info for Later Retrieval
    """
    self.active_scans[scan_id] = {
        'process': proc,  # Process object for monitoring
        'output_dir': output_dir,  # Where results are written
        'start_time': utc_now(),  # When scan started
        'config': config.dict(),  # Scan configuration
        'results_file': results_file,  # Expected output file path
    }
    
    logger.info(f"[Nuclei] Scan {scan_id} started")
    logger.info(f"[Nuclei] Results will be written to: {results_file}")
    
    return scan_id  # Return ID so we can track this scan
```

**Example Nuclei Command Generated**:
```bash
# Standard scan
docker exec linkload-nuclei nuclei \
  -u https://example.com \
  -jsonl \
  -o /shared/nuclei_results_abc123/results.jsonl \
  -rl 150 \
  -c 25 \
  -retries 2 \
  -timeout 10 \
  -mhe 30 \
  -s critical,high,medium \
  -tags cve,panel,exposure,misconfig,xss,sqli,rce,ssrf \
  -dast \
  -passive \
  -as
```

---

## PART 4: SCAN MONITORING & STATUS UPDATES

### Step 6: Monitor Scan Progress
**File**: [linkload-core/app/services/comprehensive_scanner.py](linkload-core/app/services/comprehensive_scanner.py#L680)

```python
async def _run_scanner(
    self,
    scan_id: str,
    scanner_type: str,  # "nuclei"
    target_url: str,
    options: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Step 6.1: Poll Scanner Status
    
    This runs while Nuclei is executing
    It checks progress and updates the database periodically
    """
    
    # Get Nuclei scanner instance
    scanner = self.scanners["nuclei"]
    
    # Start the scan and get back a scan_id
    scan_task_id = await scanner.start_scan(scanner_config)
    
    logger.info(f"Nuclei scan started with task ID: {scan_task_id}")
    
    """
    Step 6.2: Status Polling Loop
    
    This loop continuously checks if Nuclei is still running
    """
    wait_interval = 15  # Check every 15 seconds for standard scan
    scan_start_time = datetime.now(timezone.utc)
    
    consecutive_same_status = 0
    previous_status = None
    
    while True:
        try:
            # Get current status from Nuclei
            status = await scanner.get_scan_status(scan_task_id)
            scan_status = status.get('status')
            
            # Log status changes
            if scan_status != previous_status:
                logger.info(f"[Nuclei] Status changed to: {scan_status}")
                previous_status = scan_status
                consecutive_same_status = 0
            else:
                consecutive_same_status += 1
            
            """
            Step 6.3: Update Frontend with Progress
            
            Every status check, update the database
            Frontend polls this to show progress bar
            """
            await self._update_scan_progress(
                scan_id,
                progress=35,  # 35% for nuclei scan stage
                stage=f"Running Nuclei scan... ({scan_status})"
            )
            
            # Check if scan completed
            if scan_status == 'completed':
                logger.info("[Nuclei] Scan completed successfully!")
                break
            elif scan_status in ['failed', 'error']:
                logger.error(f"[Nuclei] Scan failed: {scan_status}")
                # Try to retrieve partial results anyway
                break
            
            # Wait before checking again
            await asyncio.sleep(wait_interval)
            
        except Exception as e:
            logger.error(f"Error checking Nuclei status: {e}")
            break
```

**Database Updates During Scan**:
```
UPDATE scans SET 
  status = 'running',
  progress = 35,
  current_stage = 'Running Nuclei scan... (running)'
WHERE scan_id = 'scan_abc123'
```

---

### Step 7: Get Scan Results
**File**: [linkload-core/app/services/scanners/nuclei_scanner.py](linkload-core/app/services/scanners/nuclei_scanner.py#L500)

```python
async def get_scan_results(self, scan_id: str) -> ScanResult:
    """
    Step 7.1: Wait for Process to Complete
    
    This reads the results file that Nuclei wrote
    """
    
    scan_info = self.active_scans[scan_id]
    results_file = scan_info['results_file']
    
    """
    Step 7.2: Ensure Process Has Exited
    
    Wait for Nuclei process to finish writing to file
    """
    proc = scan_info['process']
    
    if scan_info.get('is_windows'):
        # Windows: use communicate() in thread pool
        def wait_for_process():
            stdout, stderr = proc.communicate()
            return stdout, stderr
        
        stdout_bytes, stderr_bytes = await asyncio.get_event_loop().run_in_executor(
            self.executor,
            wait_for_process
        )
    else:
        # Linux/Mac: use asyncio communicate()
        stdout_bytes, stderr_bytes = await proc.communicate()
    
    """
    Step 7.3: Parse Results File
    
    Nuclei outputs results as JSON Lines format:
    Each line is a separate JSON object representing one finding
    """
    
    vulnerabilities = []
    
    # Open and read the results file line by line
    with open(results_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                # Parse each line as JSON
                finding = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed JSON lines
                continue
            
            # Extract finding data
            info = finding.get('info', {}) or {}
            classification = info.get('classification', {}) or {}
            
            # Step 7.4: Extract Finding Details
            template_id = finding.get('template-id') or finding.get('templateID')
            title = info.get('name') or template_id
            severity = info.get('severity', 'medium').lower()
            cvss_score = classification.get('cvss-score') or 0.0
            
            # Example finding from Nuclei:
            # {
            #   "template-id": "sql-injection-detect",
            #   "info": {
            #     "name": "SQL Injection Vulnerability",
            #     "description": "Potential SQL injection in login parameter",
            #     "severity": "critical",
            #     "tags": ["sqli", "injection", "cve"],
            #     "reference": "https://owasp.org/www-community/attacks/SQL_Injection"
            #   },
            #   "matched-at": "https://example.com/login?user=admin' OR '1'='1",
            #   "matcher-name": "expression_matcher",
            #   "classification": {
            #     "cvss-score": 9.8,
            #     "cwe-id": "CWE-89"
            #   }
            # }
            
            """
            Step 7.5: Intelligent Severity Upgrading
            
            Nuclei's severity may not always be accurate.
            We upgrade severity based on vulnerability type:
            """
            
            critical_keywords = [
                'rce', 'remote code execution', 'sql injection',
                'auth bypass', 'arbitrary file upload', 'deserialization'
            ]
            
            high_keywords = [
                'xss', 'csrf', 'open redirect', 'privilege escalation',
                'session fixation', 'api key exposure'
            ]
            
            medium_keywords = [
                'information disclosure', 'misconfiguration',
                'missing header', 'weak cipher'
            ]
            
            # Check if title contains critical keywords
            title_lower = (title or '').lower()
            tags_list = info.get('tags', [])
            if isinstance(tags_list, str):
                tags_list = tags_list.split(',')
            tags_str = ','.join(tags_list).lower()
            
            # Upgrade severity if needed
            if cvss_score >= 9.0 or any(kw in title_lower or kw in tags_str for kw in critical_keywords):
                severity = 'critical'
            elif cvss_score >= 7.0 or any(kw in title_lower or kw in tags_str for kw in high_keywords):
                if severity in ['low', 'info', 'medium']:
                    severity = 'high'
            elif any(kw in title_lower or kw in tags_str for kw in medium_keywords):
                if severity in ['low', 'info']:
                    severity = 'medium'
            
            """
            Step 7.6: Generate Enhanced Remediation Advice
            
            We add specific solutions based on vulnerability type
            """
            
            if 'sql' in title_lower.lower():
                solution = "Use parameterized queries. Implement input validation. Use ORMs."
            elif 'xss' in title_lower:
                solution = "Implement context-aware output encoding. Use CSP headers. Sanitize inputs."
            elif 'rce' in title_lower or 'command' in title_lower:
                solution = "Avoid executing system commands with user input. Use safe APIs."
            else:
                solution = info.get('remediation') or "Apply security patches. Review OWASP guidelines."
            
            """
            Step 7.7: Create Vulnerability Object
            """
            
            vuln = {
                'vuln_id': template_id,
                'title': title,
                'name': template_id,
                'severity': severity,  # critical/high/medium/low/info
                'cvss_score': cvss_score,
                'confidence': 'confirmed',
                'description': info.get('description'),
                'location': finding.get('matched-at'),  # The exact URL/path affected
                'url': finding.get('matched-at'),
                'evidence': finding.get('matcher-name'),  # How it was detected
                'recommendation': solution,
                'solution': solution,
                'references': info.get('reference', []),
                'tags': tags_list,
                'cwe_id': classification.get('cwe-id'),
                'discovered_at': utc_now(),
                'raw_finding': finding  # Store raw JSON for debugging
            }
            
            vulnerabilities.append(vuln)
    
    """
    Step 7.8: Return ScanResult Object
    
    This object contains:
    - scan_id: unique scan identifier
    - vulnerabilities: list of all findings
    - status: 'completed'
    - start_time, end_time: timestamps
    """
    
    logger.info(f"[Nuclei] Scan complete: {len(vulnerabilities)} vulnerabilities found")
    logger.info(f"[Nuclei] Severity breakdown:")
    
    severity_counts = {}
    for v in vulnerabilities:
        sev = v.get('severity', 'unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        if sev in severity_counts:
            logger.info(f"[Nuclei]   {sev.upper()}: {severity_counts[sev]}")
    
    return ScanResult(
        scan_id=scan_id,
        target_url=scan_info['config']['target_url'],
        start_time=scan_info['start_time'],
        end_time=utc_now(),
        status='completed',
        vulnerabilities=vulnerabilities,
        raw_findings={
            'command': scan_info['cmd'],
            'output_file': results_file,
            'return_code': proc.returncode
        }
    )
```

**Example Nuclei Output (JSON Lines)**:
```json
{\"template-id\":\"http-missing-headers\",\"info\":{\"name\":\"Missing Anti-CSRF Token\",\"severity\":\"medium\"},\"matched-at\":\"https://example.com/form\",\"matcher-name\":\"header_matcher\"}
{\"template-id\":\"sql-injection\",\"info\":{\"name\":\"SQL Injection\",\"severity\":\"critical\"},\"matched-at\":\"https://example.com/search?q=1' OR '1'='1\",\"matcher-name\":\"regex_matcher\"}
{\"template-id\":\"exposed-git\",\"info\":{\"name\":\"Git Repository Exposed\",\"severity\":\"high\"},\"matched-at\":\"https://example.com/.git/config\",\"matcher-name\":\"file_matcher\"}
```

---

## PART 5: RESULTS STORAGE & DATABASE

### Step 8: Store Vulnerabilities in Database
**File**: [linkload-core/app/services/comprehensive_scanner.py](linkload-core/app/services/comprehensive_scanner.py#L500)

```python
async def start_scan(self, ...):
    """
    Step 8.1: Aggregate Results from All Scanners
    
    Results from Nuclei, OWASP ZAP, Wapiti all come back as lists
    We combine them into one list
    """
    
    all_vulnerabilities = []
    
    # Run all scanners concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Nuclei results come back as a list of vulnerability dicts
    nuclei_vulns = results[0]  # If nuclei is first in task list
    
    all_vulnerabilities.extend(nuclei_vulns)
    
    logger.info(f"Aggregated {len(all_vulnerabilities)} total findings")
    
    """
    Step 8.2: Normalize All Vulnerabilities
    
    Different scanners return data in different formats
    We normalize to a standard format for database storage
    """
    
    normalized_vulns = []
    
    for vuln in all_vulnerabilities:
        normalized = {
            "vuln_id": vuln.get("vuln_id") or str(uuid.uuid4()),
            "title": vuln.get("title") or "Unknown",
            "name": vuln.get("name") or "Unknown",
            "description": vuln.get("description") or "",
            "severity": (vuln.get("severity") or "medium").lower(),
            "confidence": vuln.get("confidence") or "medium",
            "cvss_score": float(vuln.get("cvss_score") or 0.0),
            "url": vuln.get("url") or "",
            "location": vuln.get("location") or vuln.get("url") or "",
            "recommendation": vuln.get("recommendation") or vuln.get("solution") or "",
            "references": vuln.get("references") or [],
            "tags": vuln.get("tags") or [],
            "cwe_id": vuln.get("cwe_id"),
            "scanner_source": vuln.get("scanner_source") or "nuclei",
            "discovered_at": datetime.now(timezone.utc),
            "raw_finding": vuln.get("raw_finding")
        }
        normalized_vulns.append(normalized)
    
    logger.info(f"Normalized {len(normalized_vulns)} vulnerabilities")
    
    """
    Step 8.3: Insert into Database
    
    All normalized vulnerabilities are inserted into Supabase
    """
    
    if normalized_vulns:
        count = supabase.insert_vulnerabilities(scan_id, normalized_vulns)
        logger.info(f"Stored {count} vulnerabilities for scan {scan_id}")
```

**Database Table: vulnerabilities**
```
┌─────────────────────┬────────────────────────┐
│ id                  │ auto-increment uuid    │
│ scan_id             │ scan_abc123            │
│ title               │ "SQL Injection..."     │
│ severity            │ "critical"             │
│ cvss_score          │ 9.8                    │
│ url                 │ "https://example.com..." │
│ recommendation      │ "Use parameterized..." │
│ scanner_source      │ "nuclei"               │
│ tags                │ ["sqli", "injection"  │
│ discovered_at       │ 2024-01-31 10:45:30Z   │
│ raw_finding         │ { full JSON data }     │
└─────────────────────┴────────────────────────┘

100s of rows like this for each scan
```

---

### Step 9: Enhanced Analysis & Enrichment
**File**: [linkload-core/app/services/comprehensive_scanner.py](linkload-core/app/services/comprehensive_scanner.py#L550)

```python
    """
    Step 9.1: Enrich with NVD Data
    
    For CVE-based findings, fetch details from NVD (National Vulnerability Database)
    """
    
    from app.services.threat_intelligence.unified_intel_service import unified_threat_intel
    
    normalized_vulns = await unified_threat_intel.enrich_vulnerabilities_with_nvd(normalized_vulns)
    
    logger.info("Enriched vulnerabilities with NVD data")
    
    """
    Step 9.2: Enrich with Exploit Data
    
    Check if exploits exist for these vulnerabilities using Vulners API
    """
    
    normalized_vulns, vulners_summary = await self._enrich_with_vulners(
        unified_threat_intel,
        normalized_vulns
    )
    
    logger.info(f"Found {vulners_summary.get('total_exploits', 0)} exploits")
    
    """
    Step 9.3: AI-Powered Analysis
    
    Use LLM (GPT, Claude, Groq) to generate:
    - Executive summary
    - Remediation strategies
    - Risk assessment
    - Priority recommendations
    """
    
    await self._perform_ai_analysis(scan_id, normalized_vulns, options)
    
    logger.info("AI analysis completed")
    
    """
    Step 9.4: MITRE ATT&CK Mapping
    
    Map vulnerabilities to MITRE ATT&CK techniques
    Shows attacker tactics and techniques
    """
    
    await self._perform_mitre_mapping(scan_id, normalized_vulns)
    
    logger.info("MITRE mapping completed")
    
    """
    Step 9.5: Risk Assessment Calculation
    
    Calculate overall risk score (0-10):
    - Severity-weighted scoring
    - Exploit availability considered
    - Business impact factored in
    - Network exposure assessed
    """
    
    await self._calculate_risk_assessment(scan_id, normalized_vulns, threat_intel)
    
    logger.info("Risk assessment completed")
```

---

### Step 10: Mark Scan as Complete
**File**: [linkload-core/app/services/comprehensive_scanner.py](linkload-core/app/services/comprehensive_scanner.py#L620)

```python
    """
    Step 10.1: Final Status Update
    
    Update scan status to 'completed' in database
    """
    
    total_elapsed = int((datetime.now(timezone.utc) - started_at).total_seconds())
    total_mins = total_elapsed // 60
    total_secs = total_elapsed % 60
    
    await self._update_scan_progress(
        scan_id,
        status="completed",
        progress=100,
        stage=f"Completed in {total_mins}m {total_secs}s"
    )
    
    logger.info(f"Scan {scan_id} completed successfully")
```

**Final Database State**:
```
scans table UPDATE:
┌─────────────────────┬──────────────────────────┐
│ scan_id             │ scan_abc123              │
│ status              │ "completed"              │
│ progress            │ 100                      │
│ completed_at        │ 2024-01-31 10:55:30Z     │
│ summary             │ {                        │
│                     │   total_vulns: 45,       │
│                     │   critical: 2,           │
│                     │   high: 8,               │
│                     │   medium: 15,            │
│                     │   low: 20                │
│                     │ }                        │
└─────────────────────┴──────────────────────────┘

vulnerabilities table:
45 rows inserted with all details
```

---

## PART 6: FRONTEND DISPLAY & RESULTS PAGE

### Step 11: Frontend Requests Results
**Frontend Component**: ScanResults / MissionFile.jsx

```jsx
// Step 11.1: User navigates to Scan Results page
// Frontend makes API call to fetch results

const ScanResults = () => {
  useEffect(() => {
    // Step 11.2: Fetch scan results from backend
    async function fetchResults() {
      try {
        const response = await fetch(`/api/v1/scans/comprehensive/${scanId}/results`);
        const data = await response.json();
        
        // Response contains:
        // {
        //   scan_id: "scan_abc123",
        //   target_url: "https://example.com",
        //   status: "completed",
        //   vulnerabilities: [ ... 45 vulns ... ],
        //   risk_assessment: { overall_risk_score: 7.8, ... },
        //   mitre_mapping: [ ... techniques ... ],
        //   ai_analysis: [ ... analysis results ... ],
        //   executive_summary: "..."
        // }
        
        setResults(data);
      } catch (error) {
        console.error("Failed to fetch results:", error);
      }
    }
    
    fetchResults();
  }, [scanId]);
  
  return (
    <div>
      {/* Step 11.3: Display Results */}
      
      {/* Executive Summary Card */}
      <SummaryCard summary={results.executive_summary} />
      
      {/* Risk Score Gauge */}
      <RiskGauge score={results.risk_assessment.overall_risk_score} />
      
      {/* Vulnerabilities Table */}
      <VulnerabilitiesTable vulnerabilities={results.vulnerabilities} />
      
      {/* Filter by Severity */}
      <SeverityFilter
        critical={results.vulnerabilities.filter(v => v.severity === 'critical')}
        high={results.vulnerabilities.filter(v => v.severity === 'high')}
        medium={results.vulnerabilities.filter(v => v.severity === 'medium')}
        low={results.vulnerabilities.filter(v => v.severity === 'low')}
      />
      
      {/* MITRE ATT&CK Heatmap */}
      <MitreHeatmap techniques={results.mitre_mapping} />
      
      {/* AI Analysis Insights */}
      <AIInsights analysis={results.ai_analysis} />
    </div>
  );
};
```

---

### Step 12: Results API Endpoint
**File**: [linkload-core/app/api/scans.py](linkload-core/app/api/scans.py#L350)

```python
@router.get("/comprehensive/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: str,
    current_user = Depends(get_current_user),
    debug: int = 0
):
    """
    Step 12.1: Verify Ownership
    
    Only the owner can view their scan results
    """
    
    user_id = get_user_id(current_user)
    
    # Fetch scan from database
    scan = supabase.fetch_scan(scan_id)
    
    # Check if current user owns this scan
    verify_scan_ownership(scan, user_id)
    
    """
    Step 12.2: Fetch Vulnerabilities
    
    Get all vulnerabilities associated with this scan
    """
    
    vulnerabilities_raw = supabase.fetch_vulnerabilities(scan_id)
    
    # Normalize to VulnerabilityInfo objects
    vulnerabilities = [_normalize_vulnerability(v) for v in vulnerabilities_raw]
    
    logger.info(f"Returning {len(vulnerabilities)} vulnerabilities for scan {scan_id}")
    
    """
    Step 12.3: Build Risk Assessment
    
    Calculate the overall risk score and severity breakdown
    """
    
    risk_assessment_data = scan.get("risk_assessment", {})
    
    risk_assessment = RiskAssessment(
        overall_risk_score=risk_assessment_data.get("overall_risk_score", 0.0),
        risk_level=risk_assessment_data.get("risk_level", "Unknown"),
        vulnerability_count=len(vulnerabilities),
        critical_count=len([v for v in vulnerabilities if v.severity == "critical"]),
        high_count=len([v for v in vulnerabilities if v.severity == "high"]),
        medium_count=len([v for v in vulnerabilities if v.severity == "medium"]),
        low_count=len([v for v in vulnerabilities if v.severity == "low"]),
        info_count=len([v for v in vulnerabilities if v.severity == "info"])
    )
    
    """
    Step 12.4: Get AI Analysis Results
    
    Fetch AI-generated insights
    """
    
    ai_analysis_raw = scan.get("ai_analysis", [])
    ai_analysis = _normalize_ai_analysis(ai_analysis_raw)
    
    """
    Step 12.5: Get MITRE Mapping
    
    Fetch MITRE ATT&CK technique mappings
    """
    
    mitre_mapping = scan.get("mitre_mapping", [])
    
    """
    Step 12.6: Get Threat Intelligence
    
    Fetch enriched threat intel data
    """
    
    threat_intel = scan.get("threat_intel", {})
    # This includes:
    # - NVD enrichment data
    # - Exploit availability (Vulners)
    # - CVSS details
    # - References
    
    """
    Step 12.7: Get Remediation Strategies
    
    Fetch AI-generated remediation plans
    """
    
    remediation_strategies = scan.get("remediation_strategies", {})
    
    """
    Step 12.8: Get Executive Summary
    
    Fetch AI-generated executive summary for C-level reporting
    """
    
    executive_summary = scan.get("executive_summary", "")
    
    """
    Step 12.9: Optional Debug Information
    
    If debug=1 is passed, include diagnostic data
    """
    
    debug_info = None
    if debug == 1:
        debug_info = {
            "scan_types": scan.get("scan_types"),
            "scan_mode": scan.get("options", {}).get("scan_mode"),
            "duration_seconds": scan.get("duration"),
            "scanner_debug": scan.get("scanner_debug"),
        }
    
    """
    Step 12.10: Return Complete Response
    """
    
    return ScanResultsResponse(
        scan_id=scan_id,
        target_url=scan.get("target_url"),
        status=scan.get("status"),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        vulnerabilities=[
            _normalize_vulnerability(v) for v in vulnerabilities_raw
        ],
        risk_assessment=risk_assessment,
        mitre_mapping=mitre_mapping,
        ai_analysis=ai_analysis,
        remediation_strategies=remediation_strategies,
        executive_summary=executive_summary,
        threat_intel=threat_intel,
        scan_mode=scan.get("options", {}).get("scan_mode"),
        scan_types=scan.get("scan_types"),
        debug=debug_info
    )
```

---

## COMPLETE END-TO-END VISUALIZATION

### Timeline Example

```
User Action                              Backend Process                    Database Update
═════════════════════════════════════════════════════════════════════════════════════════════

User clicks                              API creates scan record
"Start Scan"                             with status: "pending"           scans: {
                                                                             scan_id,
                                                                             status: "pending"
                                         ↓                                }
                                         
                                         Background task queued
                                         ↓
                                         
                                         ComprehensiveScanner
                                         initializes all scanners
                                         ↓
                                         
                                         Updates status: "running"        scans.status: "running"
                                                                         scans.progress: 10%
                                         ↓
                                         
                                         NucleiScanner.start_scan()
                                         builds Nuclei command
                                         ↓
                                         
                                         Launches process:
                                         docker exec nuclei -u ...       scans.progress: 20%
                                         
                                         Nuclei runs:
                                         - Requests sent to target
                                         - Templates tested
                                         - Findings detected
                                         (5-10 minutes typically)
                                         ↓
                                                                         scans.progress: 35%
                                         
                                         Nuclei writes results.jsonl
                                         45 vulnerabilities found
                                         ↓
                                         
                                         NucleiScanner.get_scan_results()
                                         parses JSON output
                                         ↓
                                         
                                         Creates ScanResult object        scans.progress: 50%
                                         ↓
                                         
                                         Normalizes all vulnerabilities
                                         ↓
                                         
                                         Stores to database               vulnerabilities: 45 rows
                                                                         scans.progress: 60%
                                         ↓
                                         
                                         AI enrichment (NVD, Vulners)     scans.progress: 75%
                                         ↓
                                         
                                         AI analysis & remediation       scans.ai_analysis: {...}
                                         ↓
                                         
                                         MITRE mapping                    scans.mitre_mapping: {...}
                                         ↓
                                         
                                         Risk calculation                 scans.risk_assessment: {...}
                                         ↓
                                         
                                         Updates status: "completed"     scans: {
                                                                           status: "completed",
                                                                           progress: 100,
                                                                           completed_at: <time>
                                                                         }

User sees status                         
change to 100%                           
                                         
User clicks                              API calls supabase
"View Results"                           .fetch_vulnerabilities()
                                         .fetch_scan()
                                         ↓
                                         
                                         Returns ScanResultsResponse
                                         with all details
                                         ↓
                                         
                                                                         (No DB updates,
                                                                          just reading)

"Scan Results" page                      
displays:
- 45 vulnerabilities
- 2 critical
- 8 high  
- Risk score: 7.8/10
- AI recommendations
- MITRE techniques
- Remediation plan
- Executive summary
```

---

## KEY FILES REFERENCE

| Component | File | Purpose |
|-----------|------|---------|
| **Frontend** | `linkload-frontend/src/pages/MissionFile.jsx` | Displays scan UI and capabilities |
| **API Layer** | `linkload-core/app/api/scans.py` | REST endpoints for scan control |
| **Orchestrator** | `linkload-core/app/services/comprehensive_scanner.py` | Coordinates all scanners |
| **Nuclei Scanner** | `linkload-core/app/services/scanners/nuclei_scanner.py` | Nuclei-specific implementation |
| **Database** | `linkload-core/app/database/supabase_client.py` | Supabase integration |
| **Models** | `linkload-core/app/models/scan_models.py` | Data models and validation |
| **Vulnerabilities** | `linkload-core/app/models/vulnerability_models.py` | Vulnerability data structures |

---

## NUCLEI SCANNER CONFIGURATION

### Config File: NucleiScannerConfig
**Location**: [linkload-core/app/services/scanners/nuclei_scanner.py#L28](linkload-core/app/services/scanners/nuclei_scanner.py#L28)

```python
class NucleiScannerConfig(BaseModel):
    """Optimized configuration for Nuclei scanner"""
    binary_path: str = "nuclei"  # Path to nuclei executable
    templates_dir: str = ""  # Directory containing nuclei templates
    rate_limit: int = 150  # Requests per second (150 = fast but safe)
    concurrency: int = 25  # Parallel template workers
    bulk_size: int = 25  # Bulk HTTP requests per batch
    timeout: int = 10  # Timeout per request (seconds)
    retries: int = 2  # Retry failed requests
    max_host_error: int = 30  # Skip host after N errors
    disable_update_check: bool = False  # Check for template updates
    update_templates: bool = True  # Auto-update templates before scan
    follow_redirects: bool = True  # Follow HTTP 301/302
    follow_host_redirects: bool = True  # Follow redirects to different hosts
    system_resolvers: bool = True  # Use system DNS
    disable_clustering: bool = False  # Disable template clustering
    debug: bool = False  # Enable debug output
    use_docker: bool = False  # Use Docker container
    docker_container: str = "linkload-nuclei"  # Docker container name
```

---

## ENVIRONMENT VARIABLES

```bash
# Enable Docker mode for Nuclei
NUCLEI_USE_DOCKER=true
NUCLEI_CONTAINER=linkload-nuclei

# Or run locally (nuclei binary must be installed)
NUCLEI_USE_DOCKER=false
NUCLEI_BINARY_PATH=/path/to/nuclei

# Optional: specify templates directory
NUCLEI_TEMPLATES_PATH=/root/nuclei-templates

# Optional: enable headless browser for JS vulnerabilities
NUCLEI_ENABLE_HEADLESS=true

# Database connection
DATABASE_URL=postgresql://user:pass@host/dbname

# Supabase
SUPABASE_URL=https://project.supabase.co
SUPABASE_KEY=your_anon_key
SUPABASE_SERVICE_KEY=your_service_key
```

---

## ERROR HANDLING & TROUBLESHOOTING

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Nuclei Docker container not available" | Container not running | `docker-compose up -d` |
| "Nuclei binary not found" | Local mode but binary not installed | `apt-get install nuclei` or `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| "No vulnerabilities found" | Target may be hardened or scanner misconfigured | Check targets logs, verify Nuclei command |
| "Scan timeout" | Target too large or slow | Increase timeout or reduce concurrency |
| "Out of memory" | Too many workers or target too large | Reduce concurrency or batch size |

---

## Performance Metrics

| Metric | Quick Scan | Standard Scan | Deep Scan |
|--------|-----------|--------------|-----------|
| **Max Duration** | 60 minutes | 120 minutes | 240 minutes |
| **Rate Limit** | 150 req/s | 150 req/s | 50 req/s |
| **Concurrency** | 25 workers | 25 workers | 75 workers |
| **Template Categories** | High-priority only | High + Medium | All |
| **Severity Levels** | Critical, High, Medium | Critical, High, Medium | All |
| **DAST** | Yes | Yes | Yes |
| **Passive** | Yes | Yes | Yes |
| **Headless Browser** | No | No | Optional |
| **Typical Findings** | 5-20 | 15-50 | 30-100+ |

---

## Summary

The Nuclei scanner in LinkLoad follows this complete workflow:

1. **Initiation**: User starts scan via frontend API
2. **Queue**: Scan record created, background task queued
3. **Initialize**: ComprehensiveScanner detects available scanners
4. **Configure**: NucleiScanner builds command with appropriate flags
5. **Execute**: Nuclei process launched (Docker or local binary)
6. **Monitor**: Backend polls for progress status
7. **Parse**: Results parsed from JSON Lines output
8. **Enhance**: Vulnerabilities enriched with NVD/exploit data
9. **Analyze**: AI generates recommendations and risk scores
10. **Store**: All findings persisted to Supabase database
11. **Return**: API endpoint serves complete results to frontend
12. **Display**: Frontend renders interactive results dashboard

Every step is logged, monitored, and can be debugged via the comprehensive logging system and optional debug API parameter.
