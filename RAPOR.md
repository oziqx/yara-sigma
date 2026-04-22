# YARA & Sigma Rule Collector — Detaylı Proje Raporu

---

## 1. Projenin Amacı

Bu proje, siber güvenlik alanında kullanılan **YARA** ve **Sigma** tespit kurallarını GitHub üzerindeki açık kaynak repolardan otomatik olarak toplayan, her kuralı ayrı ayrı parse edip doğrulayan ve tek tek JSON dosyaları olarak kaydeden bir **rule collection pipeline**'ıdır.

**Ne yapar:**
- 22 farklı GitHub reposunu klonlar veya günceller
- Repo içindeki `.yar`, `.yara`, `.yml`, `.yaml` dosyalarını tarar
- Her dosyadaki her kuralı bireysel olarak ayrıştırır (parse)
- YARA kurallarını `yara.compile` ile, Sigma kurallarını `pySigma` ile doğrular
- Geçerli kuralları `output/{yara|sigma}/…` altına, geçersiz kuralları `output/fail/{yara|sigma}/…` altına JSON olarak yazar
- Sonraki çalışmalarda sadece değişen dosyaları işler (incremental diff)

**Neden gerekli:**
Tehdit istihbaratı (threat intelligence) ekipleri binlerce YARA ve Sigma kuralını farklı kaynaklardan takip eder. Bu proje, tüm kaynakları tek bir pipeline'da birleştirip normalize eder. Her kuralın hangi repodan, hangi dosyadan geldiği izlenebilir (provenance chain). JSON formatındaki çıktılar SIEM, EDR, veritabanı veya Elasticsearch gibi sistemlere kolayca import edilebilir.

---

## 2. Dizin Yapısı

```
yara-sigma/
├── yara-sigma.py              # Ana orkestratör — tüm akışı yönetir
├── requirements.txt           # Python bağımlılıkları (versiyonlu)
├── state.json                 # Çalışma durumu (otomatik oluşur)
│
├── modules/
│   ├── __init__.py            # Boş — paket tanımlayıcı
│   ├── config.py              # Sabit yapılandırma değerleri
│   ├── git_manager.py         # Git işlemleri (clone, pull, diff, scan)
│   ├── output_writer.py       # JSON dosya yazma, özet üretme
│   ├── state_manager.py       # state.json okuma/yazma (atomic)
│   └── utils.py               # Ortak yardımcı fonksiyonlar
│
├── parsers/
│   ├── __init__.py            # Boş — paket tanımlayıcı
│   ├── yara_parser.py         # YARA kural ayrıştırma ve doğrulama
│   └── sigma_parser.py        # Sigma kural ayrıştırma ve doğrulama
│
├── github/                    # Klonlanan repolar (otomatik oluşur)
│   ├── Neo23x0_signature-base/
│   ├── SigmaHQ_sigma/
│   └── ...
│
└── output/                    # Çıktı dizini (otomatik oluşur)
    ├── yara/                  # Geçerli YARA kuralları
    │   └── {repo}/{path}/{filename}/{rule_name}_{hash}.json
    ├── sigma/                 # Geçerli Sigma kuralları
    │   └── {repo}/{path}/{filename}/{rule_name}_{hash}.json
    └── fail/                  # Doğrulama geçemeyen kurallar
        ├── yara/
        └── sigma/
```

### Çıktı Dosya Yolu Örneği

Kaynak dosya:
```
github/Neo23x0_signature-base/yara/apt_turla.yar
```

İçindeki `APT_Turla_Snake` kuralı şu konuma yazılır:
```
output/yara/Neo23x0_signature-base/yara/apt_turla.yar/APT_Turla_Snake_a3f8b2c1.json
```

- `output/yara/` → kural tipi
- `Neo23x0_signature-base/` → kaynak repo
- `yara/` → repo içindeki alt dizin
- `apt_turla.yar/` → kaynak dosya adı (klasör olarak)
- `APT_Turla_Snake_a3f8b2c1.json` → kural adı + SHA-256 hash'inin ilk 8 karakteri

Hash eki, farklı kuralların aynı dosya adına sanitize edilmesi durumunda çakışmayı önler.

---

## 3. Bağımlılıklar

| Paket | Minimum Versiyon | Görev |
|-------|-----------------|-------|
| `gitpython` | >=3.1.40 | Git işlemleri (clone, pull, diff) |
| `PyYAML` | >=6.0.1 | Sigma YAML dosyalarını okuma/yazma |
| `yara-python` | >=4.3.0 | YARA kurallarını `yara.compile` ile doğrulama |
| `plyara` | >=2.1.0 | YARA kural metinlerini yapısal dict'e ayrıştırma |
| `pySigma` | >=0.10.0 | Sigma kurallarını `SigmaRule` nesnesiyle doğrulama |

`yara-python` ve `pySigma` opsiyoneldir. Kurulu değilse doğrulama devre dışı kalır ama ayrıştırma devam eder.

---

## 4. Yapılandırma — `modules/config.py`

Tüm sabit değerler bu dosyada tanımlıdır:

```python
BASE_DIR    = Path(__file__).resolve().parent.parent   # yara-sigma/
GITHUB_DIR  = BASE_DIR / "github"                      # klonlanan repolar
OUTPUT_DIR  = BASE_DIR / "output"                      # JSON çıktılar
STATE_FILE  = BASE_DIR / "state.json"                  # durum dosyası
```

### Dosya Uzantı Filtreleri

| Sabit | Değer | Açıklama |
|-------|-------|----------|
| `YARA_EXTENSIONS` | `{".yar", ".yara"}` | YARA dosyası olarak kabul edilen uzantılar |
| `SIGMA_EXTENSIONS` | `{".yml", ".yaml"}` | Sigma dosyası olarak kabul edilen uzantılar |

### Yok Sayılan Dizinler

```python
IGNORE_DIRS = {
    ".git", ".github", ".circleci", ".gitlab",
    "node_modules", "__pycache__", ".venv", "venv",
    ".idea", ".vscode", "test", "tests", "example", "examples",
}
```

Bu dizinler hem `os.walk` taramasında hem de `classify_file` filtrelemesinde atlanır.

### Repo Listesi

`REPOS` listesi, her biri `{"url": ..., "type": ...}` formatında 22 repo tanımı içerir:

| Tip | Repo Sayısı | Açıklama |
|-----|-------------|----------|
| `"yara"` | 19 | Sadece YARA kuralları taranır |
| `"sigma"` | 2 | Sadece Sigma kuralları taranır |
| `"both"` | 2 | Hem YARA hem Sigma taranır |

Öne çıkan kaynaklar:
- **Neo23x0/signature-base** — En kapsamlı açık kaynak YARA koleksiyonu
- **SigmaHQ/sigma** — Resmi Sigma kural deposu
- **elastic/protections-artifacts** — Elastic Security YARA kuralları
- **Yara-Rules/rules** — Topluluk tarafından sürdürülen YARA kuralları

---

## 5. Çalışma Akışı — Adım Adım

### 5.1 Başlatma (`main` fonksiyonu)

```
python yara-sigma.py
```

1. **Dizin hazırlığı:** `github/` dizini oluşturulur
2. **State yükleme:** `state.json` okunur. Dosya yoksa veya format versiyonu uyuşmuyorsa boş state oluşturulur
3. **Güvenli temizlik:** State boşsa (ilk çalışma veya format değişikliği) mevcut `output/` dizini `output_backup/` olarak yeniden adlandırılır. Tüm repolar başarıyla işlendikten sonra backup silinir. Process crash ederse backup korunur
4. **Çıktı dizinleri:** `output/yara/`, `output/sigma/`, `output/fail/yara/`, `output/fail/sigma/` oluşturulur
5. **Repo döngüsü:** Her repo için `process_repo` çağrılır, ardından state kaydedilir
6. **Özet:** State'teki sayaçlardan özet tablo üretilip loglanır

### 5.2 Repo İşleme (`process_repo` fonksiyonu)

Her repo için şu adımlar uygulanır:

```
┌─────────────────────────────────────────────────────┐
│                   process_repo                       │
├─────────────────────────────────────────────────────┤
│  1. clone_or_pull(url, dest)                        │
│     ├── Repo yoksa → clone (retry ile)              │
│     ├── Repo varsa → pull (retry ile)               │
│     ├── Detached HEAD → re-clone                    │
│     └── Corrupt repo → re-clone                     │
│                                                      │
│  2. head = repo.head.commit                         │
│     prev = state'teki son commit                    │
│                                                      │
│  3. Karar:                                          │
│     ├── head == prev → "Up-to-date" → ATLA          │
│     ├── İlk çalışma → scan_all_rule_files           │
│     └── Güncelleme → changed_files_between (diff)   │
│         └── Diff başarısızsa → full scan fallback    │
│                                                      │
│  4. Her dosya için process_file çağrılır            │
│  5. Silinen dosyaların çıktıları temizlenir         │
│  6. Repo'nun kural sayısı hesaplanıp state'e yazılır│
└─────────────────────────────────────────────────────┘
```

**Incremental diff mekanizması:** İlk çalışma dışında, sadece son commit'ten bu yana değişen dosyalar işlenir. Bu, her çalışmada binlerce dosyayı yeniden parse etmeyi önler.

### 5.3 Dosya İşleme (`process_file` fonksiyonu)

```
┌─────────────────────────────────────────────────────┐
│                   process_file                       │
├─────────────────────────────────────────────────────┤
│  1. Dosya var mı? → yoksa dön                       │
│  2. classify_file(rel_path, repo_type)              │
│     → "yara", "sigma" veya None                     │
│  3. source_info dict oluştur (repo, path, filename) │
│  4. Tip yara ise → extract_yara_rules               │
│     Tip sigma ise → extract_sigma_rules             │
│  5. Her kural için save_rule çağır                  │
│     → valid ise output/{tip}/ altına                │
│     → invalid ise output/fail/{tip}/ altına         │
│  6. İstatistik döndür: {yara: N, sigma: N, failed:N}│
└─────────────────────────────────────────────────────┘
```

---

## 6. Modül Detayları

---

### 6.1 `modules/git_manager.py` — Git İşlemleri

Bu modül tüm Git operasyonlarını yönetir: klonlama, güncelleme, dosya sınıflandırma, tarama ve diff.

#### Timeout Koruması

Modül yüklendiğinde iki ortam değişkeni ayarlanır:

```python
os.environ.setdefault("GIT_HTTP_LOW_SPEED_LIMIT", "1024")   # 1 KB/s minimum
os.environ.setdefault("GIT_HTTP_LOW_SPEED_TIME", "60")      # 60 saniye tolerans
```

Eğer bir git işlemi 60 saniye boyunca 1 KB/s altında hız görürse otomatik olarak kesilir. Bu, yanıt vermeyen sunucularda pipeline'ın sonsuza kadar takılmasını önler.

#### `repo_name_from_url(url) → str`

Git URL'sinden benzersiz bir klasör adı türetir.

| Girdi | Çıktı |
|-------|-------|
| `https://github.com/Neo23x0/signature-base.git` | `Neo23x0_signature-base` |
| `https://github.com/SigmaHQ/sigma.git` | `SigmaHQ_sigma` |

Format: `{github_kullanıcı}_{repo_adı}`. Bu, farklı kullanıcıların aynı isimli repolarını ayırt eder.

#### `_clone_with_retry(url, dest) → git.Repo`

Bir repoyu klonlar. İlk deneme başarısız olursa varsa yarım kalan dizini siler ve bir kez daha dener. İkinci deneme de başarısız olursa exception yukarı fırlar.

#### `clone_or_pull(url, dest) → (git.Repo, bool)`

Ana git senkronizasyon fonksiyonu. Dönüş değeri `(repo_nesnesi, yeni_klon_mu)` tuple'ıdır.

**Akış:**

```
dest dizini var mı?
├── HAYIR → _clone_with_retry ile klonla → (repo, True)
└── EVET
    ├── git.Repo açılabiliyor mu?
    │   └── HAYIR (InvalidGitRepositoryError) → sil, re-clone → (repo, True)
    ├── HEAD detached mı?
    │   └── EVET → sil, re-clone → (repo, True)
    └── pull dene
        ├── Başarılı → (repo, False)
        └── Başarısız → 1 kez daha dene
            ├── Başarılı → (repo, False)
            └── Başarısız → WARNING logla, repo eski haliyle dön → (repo, False)
```

Pull başarısız olduğunda `repo.head.commit` değişmez, dolayısıyla `process_repo` içinde `head == prev` kontrolü ile repo otomatik olarak atlanır.

#### `classify_file(rel_path, repo_type) → "yara" | "sigma" | None`

Bir dosyanın kural dosyası olup olmadığını belirler:

1. Dosya yolu `IGNORE_DIRS` içindeki bir dizinde mi? → `None`
2. Uzantı `.yar` veya `.yara` ve repo tipi `"yara"` veya `"both"` → `"yara"`
3. Uzantı `.yml` veya `.yaml` ve repo tipi `"sigma"` veya `"both"` → `"sigma"`
4. Hiçbiri → `None`

#### `scan_all_rule_files(repo_root, repo_type) → list[str]`

Tam repo taraması. `os.walk` ile tüm dosyaları gezer, `IGNORE_DIRS` içindeki dizinleri atlar, `classify_file` ile eşleşenlerin göreli yollarını döndürür. İlk çalışmada veya diff başarısız olduğunda kullanılır.

#### `changed_files_between(repo, old_hash, new_hash, repo_type=None) → (added_mod, deleted)`

İki commit arasındaki farkı hesaplar. GitPython'un `diff` API'sini kullanır.

| Değişiklik Tipi | Davranış |
|----------------|----------|
| `A` (Added) | `added_mod` listesine `b_path` eklenir |
| `M` (Modified) | `added_mod` listesine `b_path` eklenir |
| `C` (Copied) | `added_mod` listesine `b_path` eklenir |
| `R` (Renamed) | `added_mod`'a `b_path`, `deleted`'a `a_path` eklenir |
| `D` (Deleted) | `deleted` listesine `a_path` eklenir |

`repo_type` verildiğinde, sadece kural dosyaları (`classify_file` ile eşleşenler) döndürülür. README, .py, .md gibi dosyalar filtrelenir.

---

### 6.2 `parsers/yara_parser.py` — YARA Kural Ayrıştırıcı

Bu modül, YARA kural dosyalarını parse edip her kuralı ayrı ayrı doğrular.

#### Opsiyonel Bağımlılıklar

| Kütüphane | Flag | Yoksa ne olur |
|-----------|------|---------------|
| `yara-python` | `HAS_YARA` | Compile doğrulaması devre dışı kalır, tüm kurallar geçerli sayılır |
| `plyara` | `HAS_PLYARA` | Parse tamamen devre dışı kalır, boş liste döner |

#### Regex Sabitleri

**IMPORT_RE** — YARA import satırlarını yakalar:
```
import "pe"
import "math"
```

**YARA_RULE_RE** — Regex fallback için kural bloklarını yakalar:
```
[private|global] rule RuleName [: tag1 tag2] {
    ...
}
```

`re.DOTALL | re.MULTILINE` flag'leri kullanılır. `^\}` ile kapanış süslü parantezi satır başında aranır. Bu, kural içindeki string'lerdeki `}` karakterleriyle karışmayı önler.

#### Ayrıştırma Pipeline'ı

```
extract_yara_rules(file_path, source_info) → list[dict]

1. HAS_PLYARA kontrolü → False ise boş dön
2. Dosyayı oku (UTF-8, hatalı karakterleri ignore et)
3. Ön filtre: "rule " ve "{" yoksa boş dön
4. Import satırlarını çıkar → import_block
5. Tam dosyayı plyara ile parse et
   ├── Başarılı → parsed_rules listesi
   └── Başarısız → regex fallback ile parse et
6. Her kural için:
   a. rebuild_yara_rule ile ham kural metnini oluştur
   b. Tek başına compile kontrolü (compiles_alone)
   c. Import'larla compile kontrolü (compiles_with_imports)
   d. Sonuç:
      ├── Tek başına geçerli → raw = kural metni, valid = True
      ├── Import'la geçerli → raw = import + kural, valid = True
      └── Hiçbiriyle geçerli değil → raw = kural metni, valid = False
   e. Sonuç dict'i listeye ekle
7. Liste döndür
```

#### Çift Aşamalı Parse Stratejisi

**Plyara (birincil):** Dosyanın tamamını yapısal olarak parse eder. Kural adı, metadata, strings, condition gibi tüm bileşenleri dict olarak döndürür. Çoğu dosya için çalışır.

**Regex fallback (yedek):** Plyara hata verirse (bozuk dosya, desteklenmeyen sözdizimi), regex ile her kural bloğu tek tek çıkarılır ve ayrı ayrı plyara'ya verilir. Bu sayede bir dosyadaki bozuk kural diğerlerini etkilemez.

#### Doğrulama Mantığı

Her kural `yara.compile(source=...)` ile bireysel olarak doğrulanır:

```
compiles_alone?          compiles_with_imports?          Sonuç
─────────────────────────────────────────────────────────────────
     True                     (kontrol edilmez)           valid=True, raw=kural
     False                    True                        valid=True, raw=import+kural
     False                    False                       valid=False, raw=kural
```

Import'lar neden gerekli: Birçok YARA kuralı `pe`, `math`, `elf` gibi modülleri kullanır. Bu modüller `import "pe"` satırıyla dosya başında tanımlanır. `rebuild_yara_rule` bu import satırlarını çıktıya dahil etmez. Bu yüzden kural tek başına compile edilemez. `import_block` ön eki bu sorunu çözer.

#### Çıktı Dict Yapısı (Her Kural İçin)

```json
{
  "type": "yara",
  "rule_name": "APT_Turla_Snake",
  "source": {
    "repo": "Neo23x0_signature-base",
    "file_path": "yara/apt_turla.yar",
    "filename": "apt_turla.yar"
  },
  "raw": "import \"pe\"\nrule APT_Turla_Snake {\n  ...\n}",
  "parsed": {
    "rule_name": "APT_Turla_Snake",
    "metadata": [...],
    "strings": [...],
    "condition_terms": [...]
  },
  "extracted_at": "2026-03-10T14:30:00+00:00",
  "valid": true
}
```

| Alan | Tip | Açıklama |
|------|-----|----------|
| `type` | string | Daima `"yara"` |
| `rule_name` | string | Kuralın adı (plyara'dan) |
| `source` | dict | Kaynak repo, dosya yolu, dosya adı |
| `raw` | string | Compile edilebilir ham kural metni (gerekirse import dahil) |
| `parsed` | dict | Plyara'nın yapısal çıktısı (JSON-safe) |
| `extracted_at` | string | ISO 8601 formatında çıkarılma zamanı (UTC) |
| `valid` | bool | `yara.compile` doğrulamasını geçip geçmediği |

---

### 6.3 `parsers/sigma_parser.py` — Sigma Kural Ayrıştırıcı

Sigma kuralları YAML formatındadır. Her kural bir `detection:` bloğu içerir.

#### Opsiyonel Bağımlılık

| Kütüphane | Flag | Yoksa ne olur |
|-----------|------|---------------|
| `pySigma` | `HAS_PYSIGMA` | Doğrulama devre dışı, tüm kurallar `valid=True` sayılır |

#### Ayrıştırma Pipeline'ı

```
extract_sigma_rules(file_path, source_info) → list[dict]

1. Dosyayı oku (UTF-8)
2. Ön filtre: "detection:" yoksa boş dön
3. YAML belgelerini yükle (_load_documents)
4. Her belge için:
   a. _is_sigma_dict kontrolü (detection anahtarı var mı)
   b. yaml.dump ile raw YAML oluştur (sort_keys=False → orijinal sıra korunur)
   c. pySigma ile doğrula
      ├── Geçerli → valid = True
      └── Geçersiz → valid = False, WARNING logla
   d. Sonuç dict'i listeye ekle
5. Liste döndür
```

#### Multi-Document YAML Desteği

Sigma dosyaları `---` ayırıcısıyla birden fazla kural içerebilir:

```yaml
title: Kural 1
detection:
  ...
---
title: Kural 2
detection:
  ...
```

`_load_documents` fonksiyonu iki aşamalı çalışır:

1. **`yaml.safe_load_all`** ile tüm dosyayı parse etmeyi dene
2. **Başarısız olursa:** `\n---` ile split edip her bloğu ayrı `yaml.safe_load` ile dene

Bu, kısmen bozuk YAML dosyalarından bile kurtarılabilir kuralları çıkarmayı sağlar.

#### Sigma Kural Tanıma

Bir YAML belgesinin Sigma kuralı sayılması için minimum gereksinim:

```python
isinstance(doc, dict) and "detection" in doc
```

Ek alanlar (`title`, `logsource`, `status`, `level` vb.) zorunlu değildir ama pySigma doğrulamasında kontrol edilir.

#### Çıktı Dict Yapısı (Her Kural İçin)

```json
{
  "type": "sigma",
  "rule_name": "Suspicious PowerShell Encoded Command",
  "source": {
    "repo": "SigmaHQ_sigma",
    "file_path": "rules/windows/powershell/ps_encoded_cmd.yml",
    "filename": "ps_encoded_cmd.yml"
  },
  "raw": "title: Suspicious PowerShell Encoded Command\ndetection:\n  ...",
  "parsed": {
    "title": "Suspicious PowerShell Encoded Command",
    "status": "experimental",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"CommandLine|contains": "-enc"}, "condition": "selection"}
  },
  "extracted_at": "2026-03-10T14:30:00+00:00",
  "valid": true
}
```

---

### 6.4 `modules/output_writer.py` — Çıktı Yöneticisi

Bu modül, parse edilen kuralları JSON dosyaları olarak diske yazar, silme işlemlerini yönetir ve özet üretir.

#### `_sanitize(name) → str`

Kural adını dosya sistemi için güvenli hale getirir:

1. `<>:"/\|?*` ve kontrol karakterlerini `_` ile değiştirir
2. Baştaki/sondaki `.` ve boşlukları temizler
3. Boşsa `_unnamed` yapar
4. 200 karaktere kırpar

#### `save_rule(rule, repo_name, rel_file_path) → Path | None`

Tek bir kuralı JSON olarak yazar.

**Yol hesaplama:**

```
base = OUTPUT_DIR / {tip}              (valid=True ise)
base = OUTPUT_DIR / "fail" / {tip}     (valid=False ise)

hash = SHA-256(rule_name)[:8]
safe = sanitize(rule_name) + "_" + hash

dst = base / repo_name / rel_parent / rel_name / {safe}.json
```

Hash eki, farklı kuralların sanitize sonrası aynı ada dönüşmesi durumunda dosya çakışmasını önler. Örneğin:

| Orijinal Ad | Sanitize | Hash | Dosya Adı |
|-------------|----------|------|-----------|
| `Detect:Malware` | `Detect_Malware` | `a3f8b2c1` | `Detect_Malware_a3f8b2c1.json` |
| `Detect/Malware` | `Detect_Malware` | `7e2d9f04` | `Detect_Malware_7e2d9f04.json` |

#### `remove_rules_for_file(repo_name, rel_file_path)`

Bir kaynak dosya silindiğinde, o dosyadan üretilen tüm JSON'ları temizler. Hem `output/` hem `output/fail/` altında arar.

#### `count_rules_for_repo(repo_name) → dict[str, int]`

Belirli bir repo için `output/yara/{repo}/` ve `output/sigma/{repo}/` altındaki JSON dosyalarını sayar. `fail/` dizini dahil edilmez (sadece geçerli kurallar sayılır). Sonuç state'e kaydedilir.

#### `generate_summary(state) → dict[str, dict[str, int]]`

State'teki `rule_counts` alanlarından özet dict oluşturur. Disk taraması yapmaz, doğrudan cache'lenmiş sayıları kullanır. Atlanan (up-to-date) repolar için önceki çalışmanın sayıları geçerlidir.

Dönüş formatı:
```python
{
    "yara": {
        "Neo23x0_signature-base": 4523,
        "Yara-Rules_rules": 1287,
        ...
    },
    "sigma": {
        "SigmaHQ_sigma": 3102,
        ...
    }
}
```

#### `print_summary(summary)`

Özeti log'a formatlanmış tablo olarak yazar:

```
============================================================
  COLLECTION SUMMARY  (individual rules)
============================================================
  YARA rules total: 12345
    Neo23x0_signature-base                         4523
    Yara-Rules_rules                               1287
    ...
------------------------------------------------------------
  SIGMA rules total: 5678
    SigmaHQ_sigma                                  3102
    ...
------------------------------------------------------------
```

---

### 6.5 `modules/state_manager.py` — Durum Yönetimi

İşlenmiş repo'ların son commit hash'ini, işlenme zamanını ve kural sayılarını takip eder.

#### State Dosya Formatı (`state.json`)

```json
{
  "format_version": 2,
  "repos": {
    "Neo23x0_signature-base": {
      "last_commit": "abc123def456...",
      "last_processed": "2026-03-10T14:30:00+00:00",
      "rule_counts": {
        "yara": 4523,
        "sigma": 0
      }
    },
    "SigmaHQ_sigma": {
      "last_commit": "789xyz...",
      "last_processed": "2026-03-10T14:35:00+00:00",
      "rule_counts": {
        "yara": 0,
        "sigma": 3102
      }
    }
  }
}
```

| Alan | Açıklama |
|------|----------|
| `format_version` | State formatı versiyon numarası. Uyuşmazlıkta tüm repolar sıfırdan taranır |
| `repos` | Her repo için son durum bilgisi |
| `last_commit` | O repo için en son işlenen commit hash'i (40 karakter) |
| `last_processed` | ISO 8601 formatında son işlenme zamanı (UTC) |
| `rule_counts` | Geçerli kural sayıları (YARA ve Sigma ayrı ayrı) |

#### `load_state() → dict`

1. `state.json` var mı? Yoksa boş state döndür
2. JSON oku. Bozuksa (JSONDecodeError) WARNING logla, boş state döndür
3. `format_version` kontrol et. Uyuşmuyorsa INFO logla, boş state döndür
4. State'i döndür

Boş state döndürülmesi, tüm repo'ların yeniden taranmasını tetikler.

#### `save_state(state)`

**Atomic write pattern** kullanılır:

1. `tempfile.mkstemp` ile state dosyasının bulunduğu dizinde geçici dosya oluştur
2. State dict'ini JSON olarak geçici dosyaya yaz
3. `os.replace(tmp, state.json)` ile atomik olarak yer değiştir
4. Herhangi bir hata olursa geçici dosyayı sil ve hatayı fırlat

Bu pattern, yazma sırasında process crash ederse state dosyasının bozulmamasını garanti eder. `os.replace` işletim sistemi seviyesinde atomiktir.

---

### 6.6 `modules/utils.py` — Ortak Yardımcılar

#### `make_serializable(obj) → JSON-safe value`

Parser'ların ürettiği dict'lerdeki her değeri JSON'a yazılabilir hale getirir:

| Girdi Tipi | Dönüşüm |
|------------|---------|
| `dict` | Anahtarları `str`'e çevir, değerleri recursive dönüştür |
| `list`, `tuple` | Her elemanı recursive dönüştür |
| `str`, `int`, `float`, `bool`, `None` | Olduğu gibi bırak |
| Diğer (datetime, custom object vb.) | `str()` ile string'e çevir |

Bu fonksiyon hem YARA hem Sigma parser tarafından kullanılır.

---

## 7. Veri Akışı Diyagramı

```
GitHub Repos (22 kaynak)
        │
        ▼
┌─────────────────┐
│  git_manager.py │ ← clone / pull / diff
└────────┬────────┘
         │ dosya yolları listesi
         ▼
┌─────────────────────────────┐
│ classify_file (yara/sigma?) │
└──────┬──────────────┬───────┘
       │              │
       ▼              ▼
┌─────────────┐ ┌──────────────┐
│ yara_parser │ │ sigma_parser │
│             │ │              │
│ 1. plyara   │ │ 1. yaml.load │
│ 2. regex fb │ │ 2. multi-doc │
│ 3. compile  │ │ 3. pySigma   │
└──────┬──────┘ └──────┬───────┘
       │               │
       └───────┬───────┘
               │ list[dict] (rule_name, raw, parsed, valid, ...)
               ▼
    ┌──────────────────┐
    │ output_writer.py │
    └────┬─────────┬───┘
         │         │
         ▼         ▼
  output/{tip}/  output/fail/{tip}/
  (valid=True)   (valid=False)
```

---

## 8. Hata Yönetimi Stratejisi

Proje, pipeline'ın herhangi bir noktada kesintiye uğramasına karşı savunmacı bir yaklaşım benimser:

### Seviye 1: Git Katmanı

| Hata | Karşılık |
|------|----------|
| Ağ hatası (clone) | 1 kez retry, 2. başarısızlıkta exception yukarı fırlar |
| Ağ hatası (pull) | 1 kez retry, 2. başarısızlıkta WARNING logla, eski state ile devam |
| Corrupt repo | Sil, re-clone |
| Detached HEAD | Sil, re-clone |
| HTTP timeout | 60s boyunca 1KB/s altı hızda otomatik kes |

### Seviye 2: Parse Katmanı

| Hata | Karşılık |
|------|----------|
| Dosya okunamıyor | Boş liste dön, dosya atlanır |
| Plyara parse hatası | Regex fallback'e geç |
| Regex fallback'te hata | O kural bloğu atlanır, diğerleri devam eder |
| YARA compile hatası | `valid=False` olarak işaretle, `fail/` dizinine yaz |
| pySigma doğrulama hatası | `valid=False` olarak işaretle, `fail/` dizinine yaz |
| yaml.safe_load_all hatası | Blok bazlı split fallback |
| rebuild_yara_rule hatası | O kural atlanır (continue) |

### Seviye 3: Çıktı Katmanı

| Hata | Karşılık |
|------|----------|
| JSON yazma hatası | WARNING logla, None dön |
| State yazma sırasında crash | Geçici dosya silinir, state.json bozulmaz |
| Output dizini silinirken crash | Backup (`output_backup/`) korunur |

### Seviye 4: Orkestrasyon Katmanı

| Hata | Karşılık |
|------|----------|
| Tek bir repo başarısız | ERROR logla, diğer repolarla devam et |
| Diff hesaplama hatası | Full scan'a geri dön |
| State her repo sonrası kaydedilir | Crash durumunda sadece son repo kaybedilir |

---

## 9. Performans Özellikleri

### Incremental Processing

İlk çalışmadan sonra, her repo için sadece son commit'ten bu yana değişen dosyalar işlenir:

| Senaryo | İşlenen Dosya |
|---------|---------------|
| İlk çalışma | Tüm kural dosyaları (binlerce) |
| Sonraki çalışmalar | Sadece diff'teki dosyalar (onlarca) |
| Repo güncel | Hiç dosya işlenmez (atlanır) |

### Cache Tabanlı Özet

`generate_summary` fonksiyonu tüm output dizinini taramak yerine state'teki `rule_counts` cache'ini kullanır. Her repo işlendikten sonra sadece o repo'nun dizini sayılır (`count_rules_for_repo`), tüm output ağacı değil.

### Pre-filter

Her iki parser da dosya içeriğini tamamen parse etmeden önce hızlı bir ön filtre uygular:

| Parser | Ön Filtre | Atlanan Dosyalar |
|--------|-----------|-----------------|
| YARA | `"rule " not in content or "{" not in content` | Kural içermeyen .yar dosyaları |
| Sigma | `"detection:" not in content` | Detection bloğu olmayan .yml dosyaları |

---

## 10. Güvenlik Notları

- Dosya okuma `errors="ignore"` ile yapılır — bozuk encoding crash oluşturmaz
- `_sanitize` fonksiyonu path traversal karakterlerini (`/`, `\`, `..`) temizler
- `yaml.safe_load` kullanılır, `yaml.load` (unsafe) değil
- Git clone sadece HTTPS URL'ler üzerinden yapılır (repo listesinde SSH yok)
- `GIT_TERMINAL_PROMPT` ayarlanmamış — etkileşimli git prompt'u potansiyel olarak takılabilir

---

## 11. Çalıştırma

### Kurulum

```bash
cd yara-sigma
pip install -r requirements.txt
```

### İlk Çalıştırma

```bash
python yara-sigma.py
```

İlk çalışmada 22 repo klonlanır ve tüm kurallar parse edilir. İnternet hızına ve disk performansına bağlı olarak 20-60 dakika sürebilir.

### Sonraki Çalıştırmalar

```bash
python yara-sigma.py
```

Sadece güncellenen repolar ve değişen dosyalar işlenir. Genellikle birkaç dakika sürer.

### Çıktıları Kullanma

Her JSON dosyası bağımsızdır ve şu bilgileri içerir:
- `raw` — Doğrudan kullanılabilir kural metni
- `parsed` — Yapısal alanlar (programatik erişim için)
- `source` — Kuralın kaynağı (repo, dosya yolu)
- `valid` — Doğrulama durumu

Örnek kullanım senaryoları:
- Elasticsearch'e bulk import
- SIEM'e kural yükleme
- Kural değişikliği takibi (extracted_at + source)
- Geçersiz kuralları inceleme (`output/fail/` altında)
