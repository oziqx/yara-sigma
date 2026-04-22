🤖 AI Agent İçin Görev Metni (Prompt)
Rol: Sen deneyimli bir Tehdit İstihbaratı (CTI) ve Python Geliştiricisisin.

Görev: GitHub'dan klonlanmış veya dışarıdan indirilmiş, içinde çok fazla "kirli veri" (düz metin, yorumlar, loglar) barındırabilen dosyalardan (.txt, .yar, .yara, .yml, .yaml, .md) YARA ve Sigma kurallarını ayıklayan, doğrulayan ve JSON formatında dışarı aktaran bir Python otomasyon betiği yazman gerekiyor.

Kullanılacak Kütüphaneler:

re (Metin kazıma / regex için)

yara-python (YARA kurallarının sentaks doğrulaması / compile işlemi için)

plyara (Geçerli YARA kurallarını Python dictionary'sine çevirmek için)

PyYAML (YAML bloklarını ayırmak ve okumak için)

pysigma (Sigma kural formatının resmi doğrulaması için)

İş Akışı ve Beklentiler:

Ön Filtreleme: Script, dosyayı string olarak okumalıdır. Performans için önce basit bir metin araması yapmalıdır. İçinde rule  ve { (YARA için) veya title:, logsource:, detection: (Sigma için) geçmeyen dosyaları atlamalıdır.

YARA Çıkartma ve Doğrulama Pipeline'ı:

Metin içindeki tüm YARA bloklarını şu regex mantığıyla çıkar: (?s)rule\s+[a-zA-Z0-9_]+\s*\{.*?\n\}

Çıkarılan her bir kural string'ini yara.compile(source=...) ile test et. Try-except bloğu kullan, hata verenleri atla.

Compile edilebilen (geçerli) kuralları plyara ile parse et ve metadata'sını çıkar.

Sigma Çıkartma ve Doğrulama Pipeline'ı:

Kirli metin veya çoklu kural içeren dosyaları --- ayırıcısı ile bloklara böl (veya yaml.safe_load_all ile parçala).

Her bir bloğun içinde Sigma'ya ait temel anahtar kelimeleri (logsource:, detection:) ara.

Bu özellikleri taşıyan YAML bloklarını pysigma (veya PyYAML) ile yükleyerek doğrula. Try-except bloğu ile bozuk YAML/Sigma yapılarını atla.

Çıktı:

Başarıyla doğrulanmış ve parse edilmiş tüm YARA ve Sigma kurallarını yapılandırılmış bir JSON objesi (veya listesi) olarak döndür/kaydet.

Ek Kurallar: Kod temiz, iyi yorumlanmış (Türkçe veya İngilizce) ve modüler fonksiyonlar halinde (örn: extract_yara, extract_sigma) olmalıdır. Hata yönetimleri (Exception handling) kesinlikle uygulanmalıdır, çünkü veriler çok kirlidir.