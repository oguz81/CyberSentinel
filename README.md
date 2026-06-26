Hacettepe Üniversitesi Veri ve Bilgi Mühendisliği VBM695 Dönem Projesi.
# Cyber Sentinel
Cyber Sentinel, LLM tabanlı siber güvenlik RAG uygulaması projesidir. Projenin amacı, büyük dil modellerinin siber saldırıları tespit etme ve önlemedeki performanslarının değerlendirilmesidir.

Cyber Sentinel'in bilgi kaynağı MITRE ATT&CK dokümantasyonudur. ATT&CK'ın 18.1 versiyonunda bulunan işletme/kurumsal saldırı (enterprise attacks) listesi ChromaDB vektör veritabanına aktarılmıştır. Claude Opus 4.7 dil modeli ise log analiz raporlaması için kullanılmıştır. Uygulama, sunucu loglarını anlık olarak takip eder ve log analiz raporlarını kendi arayüzü olan web sayfası üzerinden sunar. 

Cyber Sentinel'in çalışma algoritması şu şekildedir:

1. Cyber Sentinel çalıştığında web arayüzü aktif hale gelir; internet erişimini ve
güvenliği denetlenecek uygulamanın erişilebilirliğini kontrol eder, erişilebilir ise log kayıtlarını takip eder.
2. Denetlenecek uygulamanın loglarına eklenen yeni log kaydını Claude Opus
4.7’ye gönderir.
3. Claude Opus 4.7 bu log kaydını ChromaDB’deki MITRE ATT&CK bilgileri ile
analiz eder.
4. Claude Opus 4.7, log kaydını bir güvenlik sorunu olarak görürse web
arayüzüne log kaydı, durum raporu, önerilen eylem ve üç hızlı önlem tuşunu
getirir. Bu hızlı önlem tuşları IP’nin engellenmesi, mevcut bağlantının
sonlandırılması ve bağlantı hızının yavaşlatılmasıdır.
5. Kullanıcı bu üç hızlı önlem tuşlarından birine bastığında Cyber Sentinel
işlemin fonksiyonunu çağırır ve eylemi gerçekleştirir.

Proje aşağıdaki test senaryolarında saldırıları başarıyla fark etmiş ve kullanıcı ekranına analiz raporu ve hızlı önlem tuşlarını getirerek uygulamanın siber saldırılara karşı etkili olabildiğini göstermiştir:

1. MITRE T1595 – Web Uygulaması Keşif Faaliyetleri (Dizin Kaba Kuvvet
Saldırısı / Directory Bruteforcing)
2. MITRE T1190 – Yerel Dosya Dahil Etme ve Dizin Geçişi (Local File
Inclusion - LFI / Path Traversal)
3. MITRE T1498 – Uygulama Katmanı Hizmet Dışı Bırakma (HTTP Flood /
Application-Layer DoS)
4. MITRE T1110 – Kaba Kuvvet Saldırısı ve Kimlik Bilgisi Doldurma (Brute
Force / Credential Stuffing)
5. MITRE T1059 – İşletim Sistemi Komut Enjeksiyonu (OS Command
Injection Probe)
6. MITRE T1505.003 – Web Kabuğu ve Arka Kapı Çalıştırma Taraması
(Web Shell / Backdoor Execution Scan)

*Güncellenecek...*
